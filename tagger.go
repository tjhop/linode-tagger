package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/linode/linodego"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

type instanceTagMap map[int][]string

func newLinodeClient() linodego.Client {
	apiKey, ok := os.LookupEnv("LINODE_TOKEN")
	if !ok {
		log.Fatal("Could not find LINODE_TOKEN, please assert it is set.")
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

func checkLinodeTagsAgainstConfig(linodes []linodego.Instance) (instanceTagMap, error) {
	validInstance := regexp.MustCompile(viper.GetString("instance_regex"))
	tagSet := viper.GetStringMapStringSlice("tags")

	// map of instance ID -> slice of tags for that instance
	linodeIDTagMap := make(instanceTagMap)

	for _, linode := range linodes {
		if validInstance.MatchString(linode.Label) {
			var newTags []string

			// check `absent` tags to remove unwanted tags
			for _, tag := range tagSet["absent"] {
				if slices.Contains(linode.Tags, tag) {
					// if a linode's existing tags doesn't contain
					// the specified tag to remove, then we can just
					// write it into the new tag set
					newTags = append(newTags, tag)
				}
			}

			// check `present` tags to ensure specific tags exist
			for _, tag := range tagSet["present"] {
				// compare filter against `newTags`, as
				// newTags == (the linode's tags - absent tags)
				if !slices.Contains(newTags, tag) {
					// if the specified tag does not exist,
					// add it into the new tag set
					newTags = append(newTags, tag)
				}
			}

			linodeIDTagMap[linode.ID] = newTags
			log.WithFields(log.Fields{
				"linode_id": linode.ID,
				"old_tags":  linode.Tags,
				"new_tags":  newTags,
			}).Debug("Linode tag set updated")
		}
	}

	return linodeIDTagMap, nil
}

func updateLinodeInstanceTags(ctx context.Context, client linodego.Client, id int, tags []string) error {
	_, err := client.UpdateInstance(ctx, id, linodego.InstanceUpdateOptions{Tags: &tags})
	if err != nil {
		return err
	}

	return nil
}

func updateAllTags(ctx context.Context, client linodego.Client, tagMap instanceTagMap) error {
	for id, tags := range tagMap {
		if err := updateLinodeInstanceTags(ctx, client, id, tags); err != nil {
			return err
		}
	}

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
	// TODO: add dry run flag/functionality

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

	// set log level based on config
	level, err := log.ParseLevel(viper.GetString("logging.level"))
	if err != nil {
		// if log level couldn't be parsed from config, default to info level
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(level)
		log.Infof("Log level set to: %s", level)
	}

	client := newLinodeClient()
	ctx := context.Background()
	linodes, err := client.ListInstances(ctx, nil)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Fatal("Failed to list Linodes")
	}

	tagMap, err := checkLinodeTagsAgainstConfig(linodes)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Failed to retrieve tag map of instances that need to be updated")
	}

	if err := updateAllTags(ctx, client, tagMap); err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Failed to apply new tag sets to instances")
	}

	// TODO: add ability to diff old vs new?
	// TODO: add 'report' type output to make it clear what's changed
}
