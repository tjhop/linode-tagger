package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/linode/linodego"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

type objectTagMap map[string]map[int][]string
type ReportMap map[string]map[string]ReportData

type ReportData struct {
	ObjectsAdded   []string
	ObjectsRemoved []string
}

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
}

func newLinodeClient() linodego.Client {
	apiKey, ok := os.LookupEnv("LINODE_TOKEN")
	if !ok {
		log.Fatal("Could not find LINODE_TOKEN environment variable, please assert it is set.")
	}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: apiKey})

	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}

	client := linodego.NewClient(oauth2Client)
	// linode api debug output is a firehose, only enable at trace
	if log.IsLevelEnabled(log.TraceLevel) {
		client.SetDebug(true)
	}
	return client
}

func compareTags(linodeObject interface{}, tagRules []TagRule) ([]string, []string, int) {
	// returns a slice of new tags, a slice of old tags, and the object ID (in order)

	var combinedNewTags, tags []string
	var objectID int

	var label string
	switch object := linodeObject.(type) {
	case linodego.Instance:
		tags = object.Tags
		label = object.Label
		objectID = object.ID
	case linodego.Volume:
		tags = object.Tags
		label = object.Label
		objectID = object.ID
	case linodego.NodeBalancer:
		tags = object.Tags
		label = *object.Label
		objectID = object.ID
	case linodego.Domain:
		tags = object.Tags
		label = object.Domain
		objectID = object.ID
	case linodego.LKECluster:
		tags = object.Tags
		label = object.Label
		objectID = object.ID
	}

	sort.Strings(tags)

	for _, rule := range tagRules {
		validObject := regexp.MustCompile(rule.Regex)

		if validObject.MatchString(label) {
			var newTags []string

			// check `absent` tags to remove unwanted tags
			for _, tag := range tags {
				if !slices.Contains(rule.Tags.Absent, tag) {
					// if this tag is not on the `absent` list,
					// we can persist it through to the new tag set
					newTags = append(newTags, tag)
				}
			}

			// check `present` tags to ensure specific tags exist
			for _, tag := range rule.Tags.Present {
				// compare filter against `newTags`, as
				// newTags == (the objects's tags - absent tags)
				if !slices.Contains(newTags, tag) {
					// if the specified tag does not exist,
					// add it into the new tag set
					newTags = append(newTags, tag)
				}
			}

			// add newTags to combined list of new tags for this object,
			// excluding duplicates
			for _, tag := range newTags {
				if !slices.Contains(combinedNewTags, tag) {
					combinedNewTags = append(combinedNewTags, tag)
				}
			}
		}
	}

	return combinedNewTags, tags, objectID
}

func logTags(combinedNewTags []string, tags []string, objectID int, objectType string) {
	if len(combinedNewTags) > 0 {
		sort.Strings(combinedNewTags)
		if !slices.Equal(tags, combinedNewTags) {
			log.WithFields(log.Fields{
				"object_id": objectID,
				"old_tags":  tags,
				"new_tags":  combinedNewTags,
				"type":      objectType,
			}).Debug("Object tag set updated")
		}
	}
}

func checkTagsAgainstConfig(
	linodeObjects []interface{}, objectTags map[string][]TagRule) (objectTagMap, error) {

	objectTagMap := make(objectTagMap)

	for _, objects := range linodeObjects {

		var combinedNewTags, tags []string
		var objectID int

		switch objects := objects.(type) {
		case []linodego.Instance:

			objectType := "linodes"
			objectTagMap[objectType] = make(map[int][]string)

			if objectTags[objectType] != nil {
				for _, linode := range objects {

					combinedNewTags, tags, objectID = compareTags(linode, objectTags[objectType])
					objectTagMap[objectType][objectID] = combinedNewTags
					logTags(combinedNewTags, tags, objectID, objectType)
				}
			}
		case []linodego.Volume:

			objectType := "volumes"
			objectTagMap[objectType] = make(map[int][]string)

			if objectTags[objectType] != nil {
				for _, volume := range objects {
					combinedNewTags, tags, objectID = compareTags(volume, objectTags[objectType])
					objectTagMap[objectType][objectID] = combinedNewTags
					logTags(combinedNewTags, tags, objectID, objectType)
				}
			}
		case []linodego.NodeBalancer:

			objectType := "nodebalancers"
			objectTagMap[objectType] = make(map[int][]string)

			if objectTags[objectType] != nil {
				for _, nodebalancer := range objects {
					combinedNewTags, tags, objectID = compareTags(nodebalancer, objectTags[objectType])
					objectTagMap[objectType][objectID] = combinedNewTags
					logTags(combinedNewTags, tags, objectID, objectType)
				}
			}
		case []linodego.Domain:

			objectType := "domains"
			objectTagMap[objectType] = make(map[int][]string)

			if objectTags[objectType] != nil {
				for _, domain := range objects {
					combinedNewTags, tags, objectID = compareTags(domain, objectTags[objectType])
					objectTagMap[objectType][objectID] = combinedNewTags
					logTags(combinedNewTags, tags, objectID, objectType)
				}
			}
		case []linodego.LKECluster:

			objectType := "lkeclusters"
			objectTagMap[objectType] = make(map[int][]string)

			if objectTags[objectType] != nil {
				for _, lkecluster := range objects {
					combinedNewTags, tags, objectID = compareTags(lkecluster, objectTags[objectType])
					objectTagMap[objectType][objectID] = combinedNewTags
					logTags(combinedNewTags, tags, objectID, objectType)
				}
			}
		}

	}

	return objectTagMap, nil
}

func updateObjectTags(ctx context.Context, client linodego.Client, id int, tags *[]string, data string) error {

	if id != 0 {
		switch data {
		case "linodes":
			updatedObject, err := client.UpdateInstance(ctx, id, linodego.InstanceUpdateOptions{Tags: tags})
			if err != nil {
				return err
			}
			sort.Strings(*tags)
			updatedTags := updatedObject.Tags
			sort.Strings(updatedTags)

			if !slices.Equal(updatedTags, *tags) {
				errString := "call to update instance failed: expected " + strings.Join(updatedTags, ", ") + ", got: " + strings.Join(*tags, ", ")
				return errors.New(errString)
			}
		case "volumes":
			updatedObject, err := client.UpdateVolume(ctx, id, linodego.VolumeUpdateOptions{Tags: tags})
			if err != nil {
				return err
			}
			sort.Strings(*tags)
			updatedTags := updatedObject.Tags
			sort.Strings(updatedTags)

			if !slices.Equal(updatedTags, *tags) {
				errString := "call to update volume failed; expected " + strings.Join(updatedTags, ", ") + ", got: " + strings.Join(*tags, ", ")
				return errors.New(errString)
			}
		case "nodebalancers":
			updatedObject, err := client.UpdateNodeBalancer(ctx, id, linodego.NodeBalancerUpdateOptions{Tags: tags})
			if err != nil {
				return err
			}
			sort.Strings(*tags)
			updatedTags := updatedObject.Tags
			sort.Strings(updatedTags)
			if !slices.Equal(updatedTags, *tags) {
				errString := "call to update nodebalancer failed; expected " + strings.Join(updatedTags, ", ") + ", got: " + strings.Join(*tags, ", ")
				return errors.New(errString)
			}
		case "domains":
			updatedObject, err := client.UpdateDomain(ctx, id, linodego.DomainUpdateOptions{Tags: *tags})
			if err != nil {
				return err
			}
			sort.Strings(*tags)
			updatedTags := updatedObject.Tags
			sort.Strings(updatedTags)
			if !slices.Equal(updatedTags, *tags) {
				errString := "call to update domain failed; expected " + strings.Join(updatedTags, ", ") + ", got: " + strings.Join(*tags, ", ")
				return errors.New(errString)
			}
		case "lkeclusters":
			updatedObject, err := client.UpdateLKECluster(ctx, id, linodego.LKEClusterUpdateOptions{Tags: tags})
			if err != nil {
				return err
			}
			sort.Strings(*tags)
			updatedTags := updatedObject.Tags
			sort.Strings(updatedTags)
			if !slices.Equal(updatedTags, *tags) {
				errString := "call to update lke_cluster failed; expected " + strings.Join(updatedTags, ", ") + ", got: " + strings.Join(*tags, ", ")
				return errors.New(errString)
			}

		}
	}

	return nil
}

func updateAllObjectTags(ctx context.Context, client linodego.Client, tagMap objectTagMap) error {
	for data := range tagMap {

		for id, tags := range tagMap[data] {
			if err := updateObjectTags(ctx, client, id, &tags, data); err != nil {
				return err
			}
		}
	}

	return nil
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
	return diff
}

func compareTagData(tags []string, t []string, label string, originalRemoveData ReportData, originalAddData ReportData) (removeData ReportData, addData ReportData, addDiff []string, removeDiff []string) {
	// our tags are different than we want - something will change. we need to populate the report
	sort.Strings(tags)
	sort.Strings(t)
	if !slices.Equal(tags, t) {
		// order of tags and object.Tags differs based on whether we're subtracting or contributing more tags
		addDiff = sliceDifference(tags, t)
		removeDiff = sliceDifference(t, tags)
		if len(removeDiff) > 0 {
			removeData.ObjectsRemoved = append(originalRemoveData.ObjectsRemoved, label)
		}
		if len(addDiff) > 0 {
			addData.ObjectsAdded = append(originalAddData.ObjectsAdded, label)
		}
	}
	return removeData, addData, addDiff, removeDiff
}

func buildReport(desiredTagMap objectTagMap, linodeObjects []interface{}) ReportMap {
	// diff of returned objectTagMap vs the object tags

	report := make(ReportMap)
	var objectType string
	// iterate through every type of linode object and see what tags should change
	for _, objects := range linodeObjects {
		switch objects := objects.(type) {
		case []linodego.Instance:
			objectType = "linodes"
			report[objectType] = make(map[string]ReportData)

			// separate data stores based on whether we're adding or removing tags
			var addDiff, removeDiff []string
			var removeData, addData ReportData
			for id, tags := range desiredTagMap[objectType] {
				for _, linode := range objects {
					if linode.ID == id {
						removeData, addData, addDiff, removeDiff = compareTagData(tags, linode.Tags, linode.Label, removeData, addData)
					}
					for _, tag := range addDiff {
						report[objectType][tag] = addData
					}
					for _, tag := range removeDiff {
						report[objectType][tag] = removeData
					}
				}
			}

		case []linodego.Volume:
			objectType = "volumes"
			report[objectType] = make(map[string]ReportData)

			var addDiff, removeDiff []string
			var removeData, addData ReportData
			for id, tags := range desiredTagMap[objectType] {
				for _, volume := range objects {
					if volume.ID == id {
						removeData, addData, addDiff, removeDiff = compareTagData(tags, volume.Tags, volume.Label, removeData, addData)
					}
					for _, tag := range addDiff {
						report[objectType][tag] = addData
					}
					for _, tag := range removeDiff {
						report[objectType][tag] = removeData
					}
				}
			}

		case []linodego.NodeBalancer:
			objectType = "nodebalancers"
			report[objectType] = make(map[string]ReportData)

			var addDiff, removeDiff []string
			var removeData, addData ReportData
			for id, tags := range desiredTagMap[objectType] {
				for _, nodebalancer := range objects {
					if nodebalancer.ID == id {
						removeData, addData, addDiff, removeDiff = compareTagData(tags, nodebalancer.Tags, *nodebalancer.Label, removeData, addData)
					}
					for _, tag := range addDiff {
						report[objectType][tag] = addData
					}
					for _, tag := range removeDiff {
						report[objectType][tag] = removeData
					}
				}
			}

		case []linodego.Domain:
			objectType = "domains"
			report[objectType] = make(map[string]ReportData)

			var addDiff, removeDiff []string
			var removeData, addData ReportData
			for id, tags := range desiredTagMap[objectType] {
				for _, domain := range objects {
					if domain.ID == id {
						removeData, addData, addDiff, removeDiff = compareTagData(tags, domain.Tags, domain.Domain, removeData, addData)
					}
					for _, tag := range addDiff {
						report[objectType][tag] = addData
					}
					for _, tag := range removeDiff {
						report[objectType][tag] = removeData
					}
				}

			}
		case []linodego.LKECluster:
			objectType = "lkeclusters"
			report[objectType] = make(map[string]ReportData)

			var addDiff, removeDiff []string
			var removeData, addData ReportData
			for id, tags := range desiredTagMap[objectType] {
				for _, lkecluster := range objects {
					if lkecluster.ID == id {
						removeData, addData, addDiff, removeDiff = compareTagData(tags, lkecluster.Tags, lkecluster.Label, removeData, addData)
					}
					for _, tag := range addDiff {
						report[objectType][tag] = addData
					}
					for _, tag := range removeDiff {
						report[objectType][tag] = removeData
					}
				}

			}

		}
	}
	return report
}

func genReport(report ReportMap) error {
	// create a pretty table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"tag", "Objects Changed", "Objects", "Object Type", "Added/Removed"})
	for objectType := range report {
		for tag, data := range report[objectType] {

			addObjectList := strings.Join(data.ObjectsAdded, ", ")
			removeObjectList := strings.Join(data.ObjectsRemoved, ", ")

			removeCount := len(data.ObjectsRemoved)
			addCount := len(data.ObjectsAdded)
			if removeCount >= 1 {
				t.AppendRow(table.Row{
					tag,
					removeCount,
					removeObjectList,
					objectType,
					"Removed",
				})
			}
			if addCount >= 1 {
				t.AppendRow(table.Row{
					tag,
					addCount,
					addObjectList,
					objectType,
					"Added"})
			}
		}
	}
	t.SetAutoIndex(true)
	t.SetColumnConfigs([]table.ColumnConfig{
		{
			WidthMax: 64,
		},
	})
	t.SetStyle(table.StyleLight)
	t.Render()
	return nil
}

func genJSON(report ReportMap) error {
	// convert ReportMap to JSON and send to stdout
	for objectType := range report {
		for tag, data := range report[objectType] {
			report[objectType][tag] = data
		}
	}
	stdout, err := json.Marshal(report)
	fmt.Println(string(stdout))

	if err != nil {
		return err
	}
	return nil
}

func init() {
	// init logging
	log.SetOutput(ioutil.Discard) // Send all logs to nowhere by default

	log.AddHook(&writer.Hook{ // Send logs to stderr, makes it easier to pipe stdout to jq for --json
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
			log.WarnLevel,
			log.InfoLevel,
			log.DebugLevel,
		},
	})

	// enable func/file logging
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			fileName := filepath.Base(f.File)
			funcName := filepath.Base(f.Function)
			return fmt.Sprintf("%s()", funcName), fmt.Sprintf("%s:%d", fileName, f.Line)
		},
	})
}

func main() {
	// prep and parse flags
	flag.String("config", "", "Path to configuration file to use")
	flag.String("logging.level", "", "Logging level may be one of: trace, debug, info, warning, error, fatal and panic")
	flag.Bool("dry-run", false, "Don't apply the tag changes")
	flag.Bool("report", false, "Report output to summarize tag changes")
	flag.Bool("json", false, "Provide changes in JSON")

	flag.Parse()
	viper.BindPFlags(flag.CommandLine)

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
			log.Fatal("Unable to find configuration file")
		} else {
			log.WithFields(log.Fields{
				"err": err,
			}).Fatal("Unable to read configuration file")
		}
	}

	var config TaggerConfig
	if err := viper.UnmarshalKey("tagger", &config); err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Fatal("Unable to marshal config file to struct")
	}

	// set log level based on config
	level, err := log.ParseLevel(viper.GetString("logging.level"))
	if err != nil {
		// if log level couldn't be parsed from config, default to info level
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(level)
		log.Infof("Log level set to: %s", level)
	}

	log.Info("Gathering objects on this account")
	client := newLinodeClient()
	ctx := context.Background()

	linodes, err := client.ListInstances(ctx, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Failed to list linodes")
	}
	volumes, err := client.ListVolumes(ctx, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Failed to list volumes")
	}
	nodebalancers, err := client.ListNodeBalancers(ctx, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Failed to list nodebalancers")
	}
	domains, err := client.ListDomains(ctx, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Failed to list domains")
	}
	lkeclusters, err := client.ListLKEClusters(ctx, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Failed to list lkeclusters")
	}

	linodeObjects := []interface{}{linodes, volumes, nodebalancers, domains, lkeclusters}

	objectTags := make(map[string][]TagRule)
	objectTags["linodes"] = config.Instances
	objectTags["volumes"] = config.Volumes
	objectTags["nodebalancers"] = config.NodeBalancers
	objectTags["domains"] = config.Domains
	objectTags["lkeclusters"] = config.LKEClusters

	log.Info("Checking linode object tags against config file")
	tagMap, err := checkTagsAgainstConfig(
		linodeObjects, objectTags)

	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Failed to retrieve tag map of objects that need to be updated")
	}

	if !viper.GetBool("dry-run") {
		log.Info("Applying new tags to objects that need updating")
		if err := updateAllObjectTags(ctx, client, tagMap); err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Failed to apply new tag sets to objects")
		}
	} else {
		log.Info("Dry run enabled, not applying tags.")
	}

	// build report data for use with report/json if requested
	report := buildReport(tagMap, linodeObjects)

	if viper.GetBool("report") {
		log.Info("Generating summary report of changes")
		genReport(report)
	}

	if viper.GetBool("json") {
		genJSON(report)
	}

	// TODO: add ability to diff old vs new?
}
