package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/linode/linodego"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

var (
	Version   string // will be populated by linker during `go build`
	BuildDate string // will be populated by linker during `go build`
	Commit    string // will be populated by linker during `go build`
)

type TagSet struct {
	Present []string `yaml:"present" mapstructure:"present"`
	Absent  []string `yaml:"absent" mapstructure:"absent"`
}
type TagRule struct {
	Regex string `yaml:"regex"`
	Tags  TagSet `yaml:"tags,omitempty" mapstructure:"tags"`
}
type TaggerConfig struct {
	Instances     []TagRule `yaml:"instances"`
	Volumes       []TagRule `yaml:"volumes"`
	NodeBalancers []TagRule `yaml:"nodebalancers"`
	Domains       []TagRule `yaml:"domains"`
	LKEClusters   []TagRule `yaml:"lke_clusters"`
	Firewalls     []TagRule `yaml:"firewalls"`
}

// LinodeObjectCollection holds a slice of each type of
// taggable object that is available from the Linode API
// via the linodego library.
type LinodeObjectCollection struct {
	Instances     []linodego.Instance
	Volumes       []linodego.Volume
	NodeBalancers []linodego.NodeBalancer
	Domains       []linodego.Domain
	LKEClusters   []linodego.LKECluster
	Firewalls     []linodego.Firewall
}

// LinodeObjectTags holds an object's ID, as well as the desired set of tags that it should have.
type LinodeObjectDesiredTags struct {
	ID  int
	Old []string
	New []string
}

type LinodeObjectDesiredTagsCollection struct {
	Instances     []LinodeObjectDesiredTags
	Domains       []LinodeObjectDesiredTags
	NodeBalancers []LinodeObjectDesiredTags
	LKEClusters   []LinodeObjectDesiredTags
	Volumes       []LinodeObjectDesiredTags
	Firewalls     []LinodeObjectDesiredTags
}

// Diff contains a list of tags that have been added/removed from a given
// object
type Diff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

type LinodeObjectDiff struct {
	ID    int    `json:"id"`
	Label string `json:"label"`
	Diff  `json:"diff"`
}

type LinodeObjectCollectionDiff struct {
	Instances     []LinodeObjectDiff `json:"instances"`
	Domains       []LinodeObjectDiff `json:"domains"`
	NodeBalancers []LinodeObjectDiff `json:"nodebalancers"`
	LKEClusters   []LinodeObjectDiff `json:"lkeclusters"`
	Volumes       []LinodeObjectDiff `json:"volumes"`
	Firewalls     []LinodeObjectDiff `json:"firewalls"`
}

func newLinodeClient() linodego.Client {
	apiKey, ok := os.LookupEnv("LINODE_TOKEN")
	if !ok {
		slog.Error("Could not find LINODE_TOKEN environment variable, please assert it is set.")
		os.Exit(1)
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: apiKey})

	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}

	client := linodego.NewClient(oauth2Client)
	// linode api debug output is a firehose, only enable if the
	// environment variable `TAGGER_LINODE_CLIENT_DEBUG` is populated
	if _, ok := os.LookupEnv("TAGGER_LINODE_CLIENT_DEBUG"); ok {
		client.SetDebug(true)
	}

	return client
}

// getTagDiff accepts 2 string slices (the current set of tags, and the desired
// set of tags). It outputs a Diff object containing the changes
func getTagDiff(have, want []string) Diff {
	var diff Diff

	sort.Strings(have)
	sort.Strings(want)
	if !slices.Equal(have, want) {
		// order of have and object.have differs based on whether we're subtracting or contributing more have
		diff.Added = sliceDifference(want, have)
		diff.Removed = sliceDifference(have, want)
	}

	return diff
}

// getLinodeObjectCollectionDiff accepts a LinodeObjectCollection and
// LinodeObjectDesiredTagsCollection, and returns a LinodeObjectCollectionDiff
// containing the diffs between the API objects and their "desired" state
func getLinodeObjectCollectionDiff(loc LinodeObjectCollection, desiredTags LinodeObjectDesiredTagsCollection) LinodeObjectCollectionDiff {
	diff := LinodeObjectCollectionDiff{}

	// instances
	for _, old := range desiredTags.Instances {
		for _, cur := range loc.Instances {
			if old.ID != cur.ID {
				continue
			}

			diff.Instances = append(diff.Instances, LinodeObjectDiff{
				ID:    cur.ID,
				Label: cur.Label,
				Diff:  getTagDiff(old.Old, cur.Tags),
			})
		}
	}

	// domains
	for _, old := range desiredTags.Domains {
		for _, cur := range loc.Domains {
			if old.ID != cur.ID {
				continue
			}

			diff.Domains = append(diff.Domains, LinodeObjectDiff{
				ID:    cur.ID,
				Label: cur.Domain,
				Diff:  getTagDiff(old.Old, cur.Tags),
			})
		}
	}

	// lke clusters
	for _, old := range desiredTags.LKEClusters {
		for _, cur := range loc.LKEClusters {
			if old.ID != cur.ID {
				continue
			}

			diff.LKEClusters = append(diff.LKEClusters, LinodeObjectDiff{
				ID:    cur.ID,
				Label: cur.Label,
				Diff:  getTagDiff(old.Old, cur.Tags),
			})
		}
	}

	// volumes
	for _, old := range desiredTags.Volumes {
		for _, cur := range loc.Volumes {
			if old.ID != cur.ID {
				continue
			}

			diff.Volumes = append(diff.Volumes, LinodeObjectDiff{
				ID:    cur.ID,
				Label: cur.Label,
				Diff:  getTagDiff(old.Old, cur.Tags),
			})
		}
	}

	// nodebalancers
	for _, old := range desiredTags.NodeBalancers {
		for _, cur := range loc.NodeBalancers {
			if old.ID != cur.ID {
				continue
			}

			diff.NodeBalancers = append(diff.NodeBalancers, LinodeObjectDiff{
				ID:    cur.ID,
				Label: *cur.Label,
				Diff:  getTagDiff(old.Old, cur.Tags),
			})
		}
	}

	// firewalls
	for _, old := range desiredTags.Firewalls {
		for _, cur := range loc.Firewalls {
			if old.ID != cur.ID {
				continue
			}

			diff.Firewalls = append(diff.Firewalls, LinodeObjectDiff{
				ID:    cur.ID,
				Label: cur.Label,
				Diff:  getTagDiff(old.Old, cur.Tags),
			})
		}
	}

	return diff
}

// getNewTags accepts an object's string label, an object's existing set of
// tags, and a slice of TagRules to apply to the given object type. The regex
// in the TagRule is matched against the provided label. This function returns
// a string slice, which is the desired set of tags that the given object
// should have according to the config, and a boolean indicating whether or not
// the given object label matched any of the configured tag rules.
func getNewTags(objectLabel string, tags []string, rules []TagRule) ([]string, bool) {
	var found bool

	if len(rules) > 0 {
		sort.Strings(tags)
		var combinedNewTags []string

		// iterate through tag rules for instances and compare
		for _, rule := range rules {
			validRegex := regexp.MustCompile(rule.Regex)

			if validRegex.MatchString(objectLabel) {
				found = true
				var newTags, expandedAbsent, expandedPresent []string

				for _, absent := range rule.Tags.Absent {
					expandedAbsent = append(expandedAbsent, validRegex.ReplaceAllString(objectLabel, absent))
				}
				for _, present := range rule.Tags.Present {
					expandedPresent = append(expandedPresent, validRegex.ReplaceAllString(objectLabel, present))
				}

				// check `absent` tags to remove unwanted tags
				for _, tag := range tags {
					if !slices.Contains(expandedAbsent, tag) {
						// if this tag is not on the `absent` list,
						// we can persist it through to the new tag set
						newTags = append(newTags, tag)
					}
				}

				// check `present` tags to ensure specific tags exist
				for _, tag := range expandedPresent {
					// compare filter against `newTags`, as
					// newTags == (the linode's tags - absent tags)
					if !slices.Contains(newTags, tag) {
						// if the specified tag does not exist,
						// add it into the new tag set
						newTags = append(newTags, tag)
					}
				}

				// add newTags to combined list of new tags for this instance,
				// excluding duplicates
				for _, tag := range newTags {
					if !slices.Contains(combinedNewTags, tag) {
						combinedNewTags = append(combinedNewTags, tag)
					}
				}
			}
		}

		sort.Strings(combinedNewTags)
		return combinedNewTags, found
	}

	return tags, found
}

func compareAllObjectTagsAgainstConfig(loc LinodeObjectCollection, config TaggerConfig) (LinodeObjectDesiredTagsCollection, LinodeObjectCollectionDiff) {
	desiredNewTags := LinodeObjectDesiredTagsCollection{}
	diff := LinodeObjectCollectionDiff{}

	// instances
	for _, instance := range loc.Instances {
		currTags := instance.Tags
		newTags, found := getNewTags(instance.Label, currTags, config.Instances)

		sort.Strings(currTags)
		sort.Strings(newTags)
		if found && !slices.Equal(currTags, newTags) {
			desiredNewTags.Instances = append(desiredNewTags.Instances, LinodeObjectDesiredTags{
				ID:  instance.ID,
				Old: currTags,
				New: newTags,
			})

			diff.Instances = append(diff.Instances, LinodeObjectDiff{
				ID:    instance.ID,
				Label: instance.Label,
				Diff:  getTagDiff(currTags, newTags),
			})
		}
	}

	// domains
	for _, domain := range loc.Domains {
		currTags := domain.Tags
		newTags, found := getNewTags(domain.Domain, currTags, config.Domains)

		sort.Strings(currTags)
		sort.Strings(newTags)
		if found && !slices.Equal(currTags, newTags) {
			desiredNewTags.Domains = append(desiredNewTags.Domains, LinodeObjectDesiredTags{
				ID:  domain.ID,
				Old: currTags,
				New: newTags,
			})

			diff.Domains = append(diff.Domains, LinodeObjectDiff{
				ID:    domain.ID,
				Label: domain.Domain,
				Diff:  getTagDiff(currTags, newTags),
			})
		}
	}

	// LKE clusters
	for _, lke := range loc.LKEClusters {
		currTags := lke.Tags
		newTags, found := getNewTags(lke.Label, currTags, config.LKEClusters)

		sort.Strings(currTags)
		sort.Strings(newTags)
		if found && !slices.Equal(currTags, newTags) {
			desiredNewTags.LKEClusters = append(desiredNewTags.LKEClusters, LinodeObjectDesiredTags{
				ID:  lke.ID,
				Old: currTags,
				New: newTags,
			})

			diff.LKEClusters = append(diff.LKEClusters, LinodeObjectDiff{
				ID:    lke.ID,
				Label: lke.Label,
				Diff:  getTagDiff(currTags, newTags),
			})
		}
	}

	// volumes
	for _, volume := range loc.Volumes {
		currTags := volume.Tags
		newTags, found := getNewTags(volume.Label, currTags, config.Volumes)

		sort.Strings(currTags)
		sort.Strings(newTags)
		if found && !slices.Equal(currTags, newTags) {
			desiredNewTags.Volumes = append(desiredNewTags.Volumes, LinodeObjectDesiredTags{
				ID:  volume.ID,
				Old: currTags,
				New: newTags,
			})

			diff.Volumes = append(diff.Volumes, LinodeObjectDiff{
				ID:    volume.ID,
				Label: volume.Label,
				Diff:  getTagDiff(currTags, newTags),
			})
		}
	}

	// nodebalancers
	for _, nb := range loc.NodeBalancers {
		currTags := nb.Tags
		newTags, found := getNewTags(*nb.Label, currTags, config.NodeBalancers)

		sort.Strings(currTags)
		sort.Strings(newTags)
		if found && !slices.Equal(currTags, newTags) {
			desiredNewTags.NodeBalancers = append(desiredNewTags.NodeBalancers, LinodeObjectDesiredTags{
				ID:  nb.ID,
				Old: currTags,
				New: newTags,
			})

			diff.NodeBalancers = append(diff.NodeBalancers, LinodeObjectDiff{
				ID:    nb.ID,
				Label: *nb.Label,
				Diff:  getTagDiff(currTags, newTags),
			})
		}
	}

	// firewalls
	for _, firewall := range loc.Firewalls {
		currTags := firewall.Tags
		newTags, found := getNewTags(firewall.Label, currTags, config.Firewalls)

		sort.Strings(currTags)
		sort.Strings(newTags)
		if found && !slices.Equal(currTags, newTags) {
			desiredNewTags.Firewalls = append(desiredNewTags.Firewalls, LinodeObjectDesiredTags{
				ID:  firewall.ID,
				Old: currTags,
				New: newTags,
			})

			diff.Firewalls = append(diff.Firewalls, LinodeObjectDiff{
				ID:    firewall.ID,
				Label: firewall.Label,
				Diff:  getTagDiff(currTags, newTags),
			})
		}
	}

	return desiredNewTags, diff
}

func updateAllObjectTags(ctx context.Context, client linodego.Client, desiredTags LinodeObjectDesiredTagsCollection) (LinodeObjectCollection, error) {
	var loc LinodeObjectCollection

	// update instance tags
	for _, i := range desiredTags.Instances {
		updatedInstance, err := client.UpdateInstance(ctx, i.ID, linodego.InstanceUpdateOptions{Tags: &i.New})
		if err != nil {
			slog.Error("Failed to update instance tags", "err", err, "id", i.ID)
			return loc, err
		}

		loc.Instances = append(loc.Instances, *updatedInstance)
	}

	// update domain tags
	for _, d := range desiredTags.Domains {
		updatedDomain, err := client.UpdateDomain(ctx, d.ID, linodego.DomainUpdateOptions{Tags: d.New})
		if err != nil {
			slog.Error("Failed to update domain tags", "err", err, "id", d.ID)
			return loc, err
		}

		loc.Domains = append(loc.Domains, *updatedDomain)
	}

	// update nodebalancer tags
	for _, nb := range desiredTags.NodeBalancers {
		updatedNodeBalancer, err := client.UpdateNodeBalancer(ctx, nb.ID, linodego.NodeBalancerUpdateOptions{Tags: &nb.New})
		if err != nil {
			slog.Error("Failed to update nodebalancer tags", "err", err, "id", nb.ID)
			return loc, err
		}

		loc.NodeBalancers = append(loc.NodeBalancers, *updatedNodeBalancer)
	}

	// update lkecluster tags
	for _, lke := range desiredTags.LKEClusters {
		updatedLKECluster, err := client.UpdateLKECluster(ctx, lke.ID, linodego.LKEClusterUpdateOptions{Tags: &lke.New})
		if err != nil {
			slog.Error("Failed to update LKE Cluster tags", "err", err, "id", lke.ID)
			return loc, err
		}

		loc.LKEClusters = append(loc.LKEClusters, *updatedLKECluster)
	}

	// update volume tags
	for _, v := range desiredTags.Volumes {
		updatedVolume, err := client.UpdateVolume(ctx, v.ID, linodego.VolumeUpdateOptions{Tags: &v.New})
		if err != nil {
			slog.Error("Failed to update v Cluster tags", "err", err, "id", v.ID)
			return loc, err
		}

		loc.Volumes = append(loc.Volumes, *updatedVolume)
	}

	// update firewall tags
	for _, f := range desiredTags.Firewalls {
		updatedFirewall, err := client.UpdateFirewall(ctx, f.ID, linodego.FirewallUpdateOptions{Tags: &f.New})
		if err != nil {
			slog.Error("Failed to update firewall tags", "err", err, "id", f.ID)
			return loc, err
		}

		loc.Firewalls = append(loc.Firewalls, *updatedFirewall)
	}

	return loc, nil
}

// sliceDifference returns the elements in `a` that aren't in `b`.
// shamelessly copied from https://stackoverflow.com/questions/19374219/how-to-find-the-difference-between-two-slices-of-strings
func sliceDifference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	sort.Strings(diff)
	return diff
}

func genJSON(diff LinodeObjectCollectionDiff) error {
	bytes, err := json.Marshal(diff)
	if err != nil {
		return err
	}

	fmt.Println(string(bytes))
	return nil
}

func version() {
	fmt.Printf("Tagger Build Information\nVersion: %s\nBuild Date: %s\nCommit: %s\nGo Version: %s\n",
		Version,
		BuildDate,
		Commit,
		runtime.Version(),
	)
}

func main() {
	// prep and parse flags
	flag.String("config", "", "Path to configuration file to use")
	flag.String("logging.level", "", "Logging level may be one of: [debug, info, warn, error]")
	flag.Bool("dry-run", false, "Don't apply the tag changes")
	flag.Bool("json", false, "Provide changes in JSON")
	flag.BoolP("version", "v", false, "Print version information about this build of tagger")

	flag.Parse()
	if err := viper.BindPFlags(flag.CommandLine); err != nil {
		panic(fmt.Errorf("Failed to parse command line flags: %s\n", err.Error()))
	}

	logLevel := slog.LevelVar{}
	logHandlerOpts := &slog.HandlerOptions{
		Level:     &logLevel,
		AddSource: true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, logHandlerOpts))
	slog.SetDefault(logger)

	if viper.GetBool("version") {
		version()
		os.Exit(0)
	}

	// get config
	configFile := viper.GetString("config")
	viper.SetConfigType("yaml")
	if configFile != "" {
		// config file set by flag, use that
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("tagger")
		viper.AddConfigPath(filepath.Join("etc", "tagger"))
		viper.AddConfigPath(filepath.Join("$HOME", ".config", "tagger"))
		viper.AddConfigPath(".")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Error("Unable to find configuration file")
			os.Exit(1)
		} else {
			slog.Error("Unable to read configuration file", "err", err)
			os.Exit(1)
		}
	}

	var config TaggerConfig
	if err := viper.UnmarshalKey("tagger", &config); err != nil {
		slog.Error("Unable to marshal config file to struct", "err", err)
		os.Exit(1)
	}

	// parse log level from flag/config
	logLevelFlagVal := strings.ToLower(viper.GetString("logging.level"))
	switch logLevelFlagVal {
	case "":
		logLevel.Set(slog.LevelInfo)
		logger.Warn("Log level flag not set, defaulting to <info> level")
	case "info": // default is info, we're good
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
		logger.Warn("Failed to parse log level from flag, defaulting to <info> level", "err", "Unsupported log level", "log_level", logLevelFlagVal)
	}

	tagger(config)
}

func tagger(config TaggerConfig) {
	slog.Info("Gathering objects on this account")
	client := newLinodeClient()
	ctx := context.Background()

	var loc LinodeObjectCollection
	if len(config.Instances) > 0 {
		linodes, err := client.ListInstances(ctx, nil)
		if err != nil {
			slog.Error("Failed to list linodes", "err", err)
			os.Exit(1)
		}
		loc.Instances = linodes
	}

	if len(config.Volumes) > 0 {
		volumes, err := client.ListVolumes(ctx, nil)
		if err != nil {
			slog.Error("Failed to list volumes", "err", err)
			os.Exit(1)
		}
		loc.Volumes = volumes
	}

	if len(config.NodeBalancers) > 0 {
		nodebalancers, err := client.ListNodeBalancers(ctx, nil)
		if err != nil {
			slog.Error("Failed to list nodebalancers", "err", err)
			os.Exit(1)
		}
		loc.NodeBalancers = nodebalancers
	}

	if len(config.Domains) > 0 {
		domains, err := client.ListDomains(ctx, nil)
		if err != nil {
			slog.Error("Failed to list domains", "err", err)
			os.Exit(1)
		}
		loc.Domains = domains
	}

	if len(config.LKEClusters) > 0 {
		lkeclusters, err := client.ListLKEClusters(ctx, nil)
		if err != nil {
			slog.Error("Failed to list lkeclusters", "err", err)
			os.Exit(1)
		}
		loc.LKEClusters = lkeclusters
	}

	if len(config.Firewalls) > 0 {
		firewalls, err := client.ListFirewalls(ctx, nil)
		if err != nil {
			slog.Error("Failed to list firewalls", "err", err)
			os.Exit(1)
		}
		loc.Firewalls = firewalls
	}

	slog.Info("Checking linode object tags against config file")
	desiredTags, tagDiff := compareAllObjectTagsAgainstConfig(loc, config)

	if !viper.GetBool("dry-run") {
		slog.Info("Applying new tags to objects that need updating")
		newLoc, err := updateAllObjectTags(ctx, client, desiredTags)
		if err != nil {
			slog.Error("Failed to apply new tag sets to objects", "err", err)
		}
		tagDiff = getLinodeObjectCollectionDiff(newLoc, desiredTags)
	} else {
		slog.Info("Dry run enabled, not applying tags.")
	}

	if viper.GetBool("json") {
		if err := genJSON(tagDiff); err != nil {
			slog.Error("Failed to generate JSON report output", "err", err)
		}
	}
}
