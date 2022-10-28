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

	"github.com/linode/linodego"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
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

// LinodeObjectCollection holds a slice of each type of
// taggable object that is available from the Linode API
// via the linodego library.
type LinodeObjectCollection struct {
	Instances     []linodego.Instance
	Volumes       []linodego.Volume
	NodeBalancers []linodego.NodeBalancer
	Domains       []linodego.Domain
	LKEClusters   []linodego.LKECluster
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

// getTagDiff accepts 2 string slices (the current set of tags, and the desired
// set of tags). It outputs a Diff object containing the changes
func getTagDiff(have, want []string) Diff {
	var d Diff

	sort.Strings(have)
	sort.Strings(want)
	if !slices.Equal(have, want) {
		// order of have and object.have differs based on whether we're subtracting or contributing more have
		d.Added = sliceDifference(want, have)
		d.Removed = sliceDifference(have, want)
	}

	return d
}

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

	return diff
}

// getNewTags accepts an object's string label, an object's existing set of
// tags, and a slice of TagRules to apply to the given object type. The regex
// in the TagRule is matched against the provided label. This function returns
// a string slice, which is the desired set of tags that the given object
// should have according to the config.
func getNewTags(objectLabel string, tags []string, rules []TagRule) []string {
	if len(rules) > 0 {
		sort.Strings(tags)
		var combinedNewTags []string

		// iterate through tag rules for instances and compare
		for _, rule := range rules {
			validRegex := regexp.MustCompile(rule.Regex)

			if validRegex.MatchString(objectLabel) {
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

		return combinedNewTags
	}

	return tags
}

func compareAllObjectTagsAgainstConfig(loc LinodeObjectCollection, config TaggerConfig) (LinodeObjectDesiredTagsCollection, LinodeObjectCollectionDiff) {
	desiredNewTags := LinodeObjectDesiredTagsCollection{}
	diff := LinodeObjectCollectionDiff{}

	// instances
	for _, instance := range loc.Instances {
		newTags := getNewTags(instance.Label, instance.Tags, config.Instances)

		desiredNewTags.Instances = append(desiredNewTags.Instances, LinodeObjectDesiredTags{
			ID:  instance.ID,
			Old: instance.Tags,
			New: newTags,
		})

		diff.Instances = append(diff.Instances, LinodeObjectDiff{
			ID:    instance.ID,
			Label: instance.Label,
			Diff:  getTagDiff(instance.Tags, newTags),
		})
	}

	// domains
	for _, domain := range loc.Domains {
		newTags := getNewTags(domain.Domain, domain.Tags, config.Domains)

		desiredNewTags.Domains = append(desiredNewTags.Domains, LinodeObjectDesiredTags{
			ID:  domain.ID,
			Old: domain.Tags,
			New: newTags,
		})

		diff.Domains = append(diff.Domains, LinodeObjectDiff{
			ID:    domain.ID,
			Label: domain.Domain,
			Diff:  getTagDiff(domain.Tags, newTags),
		})
	}

	// LKE clusters
	for _, lke := range loc.LKEClusters {
		newTags := getNewTags(lke.Label, lke.Tags, config.LKEClusters)

		desiredNewTags.LKEClusters = append(desiredNewTags.LKEClusters, LinodeObjectDesiredTags{
			ID:  lke.ID,
			Old: lke.Tags,
			New: newTags,
		})

		diff.LKEClusters = append(diff.LKEClusters, LinodeObjectDiff{
			ID:    lke.ID,
			Label: lke.Label,
			Diff:  getTagDiff(lke.Tags, newTags),
		})
	}

	// volumes
	for _, volume := range loc.Volumes {
		newTags := getNewTags(volume.Label, volume.Tags, config.Volumes)

		desiredNewTags.Volumes = append(desiredNewTags.Volumes, LinodeObjectDesiredTags{
			ID:  volume.ID,
			Old: volume.Tags,
			New: newTags,
		})

		diff.Volumes = append(diff.Volumes, LinodeObjectDiff{
			ID:    volume.ID,
			Label: volume.Label,
			Diff:  getTagDiff(volume.Tags, newTags),
		})
	}

	// nodebalancers
	for _, nb := range loc.NodeBalancers {
		newTags := getNewTags(*nb.Label, nb.Tags, config.NodeBalancers)

		desiredNewTags.NodeBalancers = append(desiredNewTags.NodeBalancers, LinodeObjectDesiredTags{
			ID:  nb.ID,
			Old: nb.Tags,
			New: newTags,
		})

		diff.NodeBalancers = append(diff.NodeBalancers, LinodeObjectDiff{
			ID:    nb.ID,
			Label: *nb.Label,
			Diff:  getTagDiff(nb.Tags, newTags),
		})
	}

	return desiredNewTags, diff
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

func updateAllObjectTags(ctx context.Context, client linodego.Client, desiredTags LinodeObjectDesiredTagsCollection) (LinodeObjectCollection, error) {
	var loc LinodeObjectCollection

	// update instance tags
	for _, i := range desiredTags.Instances {
		updatedInstance, err := client.UpdateInstance(ctx, i.ID, linodego.InstanceUpdateOptions{Tags: &i.New})
		if err != nil {
			log.WithFields(log.Fields{
				"id":    i.ID,
				"error": err,
			}).Error("Failed to update instance tags")
			return loc, err
		}

		loc.Instances = append(loc.Instances, *updatedInstance)
	}

	// update domain tags
	for _, d := range desiredTags.Domains {
		updatedDomain, err := client.UpdateDomain(ctx, d.ID, linodego.DomainUpdateOptions{Tags: d.New})
		if err != nil {
			log.WithFields(log.Fields{
				"id":    d.ID,
				"error": err,
			}).Error("Failed to update domain tags")
			return loc, err
		}

		loc.Domains = append(loc.Domains, *updatedDomain)
	}

	// update nodebalancer tags
	for _, nb := range desiredTags.NodeBalancers {
		updatedNodeBalancer, err := client.UpdateNodeBalancer(ctx, nb.ID, linodego.NodeBalancerUpdateOptions{Tags: &nb.New})
		if err != nil {
			log.WithFields(log.Fields{
				"id":    nb.ID,
				"error": err,
			}).Error("Failed to update nodebalancer tags")
			return loc, err
		}

		loc.NodeBalancers = append(loc.NodeBalancers, *updatedNodeBalancer)
	}

	// update lkecluster tags
	for _, lke := range desiredTags.LKEClusters {
		updatedLKECluster, err := client.UpdateLKECluster(ctx, lke.ID, linodego.LKEClusterUpdateOptions{Tags: &lke.New})
		if err != nil {
			log.WithFields(log.Fields{
				"id":    lke.ID,
				"error": err,
			}).Error("Failed to update LKE Cluster tags")
			return loc, err
		}

		loc.LKEClusters = append(loc.LKEClusters, *updatedLKECluster)
	}

	// update volume tags
	for _, v := range desiredTags.Volumes {
		updatedVolume, err := client.UpdateVolume(ctx, v.ID, linodego.VolumeUpdateOptions{Tags: &v.New})
		if err != nil {
			log.WithFields(log.Fields{
				"id":    v.ID,
				"error": err,
			}).Error("Failed to update v Cluster tags")
			return loc, err
		}

		loc.Volumes = append(loc.Volumes, *updatedVolume)
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

func genJSON(diff LinodeObjectCollectionDiff) error {
	bytes, err := json.Marshal(diff)
	if err != nil {
		return err
	}

	fmt.Println(string(bytes))
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

func version() {
	fmt.Printf("Tagger Build Information\nVersion: %s\nBuild Date: %s\nCommit: %s\n",
		Version,
		BuildDate,
		Commit,
	)
}

func main() {
	// prep and parse flags
	flag.String("config", "", "Path to configuration file to use")
	flag.String("logging.level", "", "Logging level may be one of: trace, debug, info, warning, error, fatal and panic")
	flag.Bool("dry-run", false, "Don't apply the tag changes")
	flag.Bool("json", false, "Provide changes in JSON")
	flag.BoolP("version", "v", false, "Print version information about this build of tagger")

	flag.Parse()
	if err := viper.BindPFlags(flag.CommandLine); err != nil {
		log.Fatal("Unable to bind flags")
	}

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

	tagger(config)
}

func tagger(config TaggerConfig) {
	log.Info("Gathering objects on this account")
	client := newLinodeClient()
	ctx := context.Background()

	var loc LinodeObjectCollection
	if len(config.Instances) > 0 {
		linodes, err := client.ListInstances(ctx, nil)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("Failed to list linodes")
		}
		loc.Instances = linodes
	}

	if len(config.Volumes) > 0 {
		volumes, err := client.ListVolumes(ctx, nil)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("Failed to list volumes")
		}
		loc.Volumes = volumes
	}

	if len(config.NodeBalancers) > 0 {
		nodebalancers, err := client.ListNodeBalancers(ctx, nil)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("Failed to list nodebalancers")
		}
		loc.NodeBalancers = nodebalancers
	}

	if len(config.Domains) > 0 {
		domains, err := client.ListDomains(ctx, nil)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("Failed to list domains")
		}
		loc.Domains = domains
	}

	if len(config.LKEClusters) > 0 {
		lkeclusters, err := client.ListLKEClusters(ctx, nil)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Fatal("Failed to list lkeclusters")
		}
		loc.LKEClusters = lkeclusters
	}

	log.Info("Checking linode object tags against config file")
	// TODO: fix actually use tag diff in dry run
	desiredTags, tagDiff := compareAllObjectTagsAgainstConfig(loc, config)

	if !viper.GetBool("dry-run") {
		log.Info("Applying new tags to objects that need updating")
		newLoc, err := updateAllObjectTags(ctx, client, desiredTags)
		if err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Failed to apply new tag sets to objects")
		}
		tagDiff = getLinodeObjectCollectionDiff(newLoc, desiredTags)
	} else {
		log.Info("Dry run enabled, not applying tags.")
	}


	// build report data for use with report/json if requested
	// report := buildReport(tagMap, linodeObjects)

	if viper.GetBool("json") {
		if err := genJSON(tagDiff); err != nil {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Failed to generate JSON report output")
		}
	}

	// TODO: add ability to diff old vs new?
}
