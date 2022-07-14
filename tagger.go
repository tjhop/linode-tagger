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

type instanceTagMap map[int][]string
type ReportMap map[string]ReportData

type ReportData struct {
	InstancesAdded   []string
	InstancesRemoved []string
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
	Instances []TagRule `yaml:"instances"`
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

func checkLinodeTagsAgainstConfig(linodes []linodego.Instance, rules []TagRule) (instanceTagMap, error) {
	linodeIDTagMap := make(instanceTagMap)

	for _, linode := range linodes {
		tags := linode.Tags
		sort.Strings(tags)
		var combinedNewTags []string
		for _, rule := range rules {
			validInstance := regexp.MustCompile(rule.Regex)

			if validInstance.MatchString(linode.Label) {
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

		if len(combinedNewTags) > 0 {
			linodeIDTagMap[linode.ID] = combinedNewTags
			sort.Strings(combinedNewTags)
			if !slices.Equal(tags, combinedNewTags) {
				log.WithFields(log.Fields{
					"linode_id": linode.ID,
					"old_tags":  tags,
					"new_tags":  combinedNewTags,
				}).Debug("Linode tag set updated")
			}
		}
	}

	return linodeIDTagMap, nil
}

func updateLinodeInstanceTags(ctx context.Context, client linodego.Client, id int, tags *[]string) error {
	updatedInstance, err := client.UpdateInstance(ctx, id, linodego.InstanceUpdateOptions{Tags: tags})
	if err != nil {
		return err
	}

	sort.Strings(*tags)
	updatedTags := updatedInstance.Tags
	sort.Strings(updatedTags)
	if !slices.Equal(updatedTags, *tags) {
		return errors.New("Call to update instance did not result in the expected tag set")
	}

	return nil
}

func updateAllInstanceTags(ctx context.Context, client linodego.Client, tagMap instanceTagMap) error {
	for id, tags := range tagMap {
		if err := updateLinodeInstanceTags(ctx, client, id, &tags); err != nil {
			return err
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

func buildReport(desiredTagMap instanceTagMap, linodes []linodego.Instance) (ReportMap) {
	// diff of returned instanceTagMap vs the instance tags
	report := make(ReportMap)

	for id, tags := range desiredTagMap {
		// separate data stores based on whether we're adding or removing tags
		var removeData, addData ReportData
		var addDiff, removeDiff []string

		for _, linode := range linodes {
			if linode.ID == id {
				// our tags are different than we want - something will change. we need to populate the report
				sort.Strings(tags)
				t := linode.Tags
				sort.Strings(t)
				if !slices.Equal(tags, t) {
					// order of tags and linode.Tags differs based on whether we're subtracting or contributing more tags
					addDiff = sliceDifference(tags, t)
					removeDiff = sliceDifference(t, tags)
					if len(removeDiff) > 0 {
						removeData.InstancesRemoved = append(removeData.InstancesRemoved, linode.Label)
					}
					if len(addDiff) > 0 {
						addData.InstancesAdded = append(addData.InstancesAdded, linode.Label)
					}
				}
			}
		}
		for _, tag := range addDiff {
			report[tag] = addData
		}
		for _, tag := range removeDiff {
			report[tag] = removeData
		}
	}

	return report
}

func genReport(report ReportMap) error {
	// create a pretty table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"tag", "Linodes Changed", "Linodes", "Added/Removed"})
	for tag, data := range report {

		addInstanceList := strings.Join(data.InstancesAdded, ", ")
		removeInstanceList := strings.Join(data.InstancesRemoved, ", ")

		fmt.Println("add list", addInstanceList)
		fmt.Println("rm list", removeInstanceList)

		removeCount := len(data.InstancesRemoved)
		addCount := len(data.InstancesAdded)
		if removeCount >= 1 {
			t.AppendRow(table.Row{
				tag,
				removeCount,
				removeInstanceList,
				"Removed",
			})
		}
		if addCount >= 1 {
			t.AppendRow(table.Row{
				tag,
				addCount,
				addInstanceList,
				"Added"})
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
	for tag, data := range report {
		report[tag] = data
	}
	stdout, err := json.Marshal(report)
	fmt.Println(string(stdout))

	if err == nil {
		return nil
	} else {
		return err
	}
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

	log.Info("Gathering linode instances on this account")
	client := newLinodeClient()
	ctx := context.Background()
	linodes, err := client.ListInstances(ctx, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Failed to list Linodes")
	}

	log.Info("Checking linode instance tags against config file")
	tagMap, err := checkLinodeTagsAgainstConfig(linodes, config.Instances)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Failed to retrieve tag map of instances that need to be updated")
	}

	if !viper.GetBool("dry-run") {
		log.Info("Applying new tags to instances that need updating")
		if err := updateAllInstanceTags(ctx, client, tagMap); err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Failed to apply new tag sets to instances")
		}
	} else {
		log.Info("Dry run enabled, not applying tags.")
	}

	// build report data for use with report/json if requested
	report := buildReport(tagMap, linodes)

	if viper.GetBool("report") {
		log.Info("Generating summary report of changes.")
		genReport(report)
	}

	if viper.GetBool("json") {
		genJSON(report)
	}

	// TODO: add ability to diff old vs new?
}
