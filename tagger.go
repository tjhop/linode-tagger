package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
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
	AddCount    int
	RemoveCount int
	Instances   string
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
		var combinedNewTags []string
		for _, rule := range rules {
			validInstance := regexp.MustCompile(rule.Regex)

			if validInstance.MatchString(linode.Label) {
				var newTags []string

				// check `absent` tags to remove unwanted tags
				for _, tag := range linode.Tags {
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
			if !slices.Equal(linode.Tags, combinedNewTags) {
				log.WithFields(log.Fields{
					"linode_id": linode.ID,
					"old_tags":  linode.Tags,
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

	if !slices.Equal(updatedInstance.Tags, *tags) {
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

// need to dereference struct pointers
func (d *ReportData) updateDataAddCount(data int) {
	d.AddCount = data
}

func (d *ReportData) updateDataRemoveCount(data int) {
	d.RemoveCount = data
}

func (d *ReportData) updateDataInstances(data string) {
	d.Instances = data
}

// strings.Builder is a more efficient way to concatenate our Linode instances
func strBuild(strs ...string) string {
	var sb strings.Builder
	for _, str := range strs {
		sb.WriteString(str)
	}
	return sb.String()
}

func buildReport(desiredTagMap instanceTagMap, linodes []linodego.Instance) (ReportMap, error) {
	// diff of returned instanceTagMap vs the instance tags
	report := make(ReportMap)
	// separate data stores based on whether we're adding or removing tags
	var removeData, addData ReportData
	mutableRemoveData := &removeData
	mutableAddData := &addData

	for id, tags := range desiredTagMap {
		var addDiff, removeDiff []string

		for _, linode := range linodes {
			if linode.ID == id {
				// our tags are different than we want - something will change. we need to populate the report
				if !reflect.DeepEqual(tags, linode.Tags) {
					// order of tags and linode.Tags differs based on whether we're subtracting or contributing more tags
					addDiff = sliceDifference(tags, linode.Tags)
					removeDiff = sliceDifference(linode.Tags, tags)
					if len(removeDiff) > 0 {
						mutableRemoveData.RemoveCount += 1
						mutableRemoveData.updateDataRemoveCount(removeData.RemoveCount)
						str := strBuild(linode.Label, ", ", mutableRemoveData.Instances)
						mutableRemoveData.updateDataInstances(str)
					}
					if len(addDiff) > 0 {
						mutableAddData.AddCount += 1
						mutableAddData.updateDataAddCount(addData.AddCount)
						str := strBuild(linode.Label, ", ", mutableAddData.Instances)
						mutableAddData.updateDataInstances(str)
					}

				}
			}
		}
		report[strings.Join(addDiff, ",")] = addData
		report[strings.Join(removeDiff, ",")] = removeData
	}
	return report, nil
}

func genReport(report ReportMap) error {
	// create a pretty table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"tag", "Linodes Changed", "Linodes", "Added/Removed"})
	for tag, data := range report {
		if data.RemoveCount > 0 {
			t.AppendRow(table.Row{
				tag,
				data.RemoveCount,
				strings.TrimSuffix(data.Instances, ", "),
				"Removed",
			})
		}
		if data.AddCount > 0 {
			t.AppendRow(table.Row{
				tag,
				data.AddCount,
				strings.TrimSuffix(data.Instances, ", "),
				"Added"})
		}
	}
	t.SetAutoIndex(true)
	t.SetColumnConfigs([]table.ColumnConfig{
		{
			WidthMax:          64,
		},
	})
	t.SetStyle(table.StyleLight)
	t.Render()
	return nil
}

func init() {
	// init logging
	log.SetOutput(ioutil.Discard) // Send all logs to nowhere by default

	log.AddHook(&writer.Hook{ // Send logs with level higher than warning to stderr
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
			log.WarnLevel,
		},
	})
	log.AddHook(&writer.Hook{ // Send info and debug logs to stdout
		Writer: os.Stdout,
		LogLevels: []log.Level{
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

	log.Info("Comparing desired tags against currently applied tags")
	report, err := buildReport(tagMap, linodes)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Failed to desired tags against currently applied tags")
	}

	if viper.GetBool("report") {
		// spew report
		genReport(report)
	}

	// TODO: add ability to diff old vs new?
}
