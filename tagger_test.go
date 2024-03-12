package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetTagDiff(t *testing.T) {
	tests := map[string]struct {
		diff       Diff
		have, want []string
	}{
		"equal": {
			have: []string{"apple", "banana", "orange"},
			want: []string{"apple", "banana", "orange"},
			diff: Diff{
				Added:   nil,
				Removed: nil,
			},
		},
		"missing": {
			have: []string{"apple", "orange"},
			want: []string{"apple", "banana", "orange"},
			diff: Diff{
				Added:   []string{"banana"},
				Removed: nil,
			},
		},
		"extra": {
			have: []string{"apple", "banana", "orange", "pickle", "onion"},
			want: []string{"apple", "banana", "orange"},
			diff: Diff{
				Added:   nil,
				Removed: []string{"onion", "pickle"},
			},
		},
		"empty": {
			have: nil,
			want: []string{"apple", "banana", "orange"},
			diff: Diff{
				Added:   []string{"apple", "banana", "orange"},
				Removed: nil,
			},
		},
		"mixed": {
			have: []string{"aplpe", "pickle", "BaNaNa", "foobar", "orange", "asdf", "testing123"},
			want: []string{"apple", "banana", "orange"},
			diff: Diff{
				Added:   []string{"apple", "banana"},
				Removed: []string{"BaNaNa", "aplpe", "asdf", "foobar", "pickle", "testing123"},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := getTagDiff(tc.have, tc.want)

			require.Equal(t, tc.diff, got)
		})
	}
}

func TestGetNewTags(t *testing.T) {
	tests := map[string]struct {
		label       string
		tags        []string
		rules       []TagRule
		desiredTags []string
		found       bool
	}{
		"no_match": {
			label:       "foo",
			tags:        []string{"apple", "banana"},
			rules:       []TagRule{{Regex: "blah", Tags: TagSet{Present: []string{"apple"}, Absent: []string{"asdf"}}}},
			desiredTags: nil,
			found:       false,
		},
		"no_rules": {
			label:       "foo",
			tags:        []string{"apple", "banana"},
			rules:       []TagRule{},
			desiredTags: []string{"apple", "banana"},
			found:       false,
		},
		"updated_rules": {
			label:       "foo",
			tags:        []string{"orange", "asdf", "banana"},
			rules:       []TagRule{{Regex: "foo", Tags: TagSet{Present: []string{"apple"}, Absent: []string{"asdf"}}}},
			desiredTags: []string{"apple", "banana", "orange"},
			found:       true,
		},
		"regex_capture_groups": {
			label:       "foo01_us-southeast_testing",
			tags:        []string{"orange", "asdf", "banana"},
			rules:       []TagRule{{Regex: "^foo\\d{2}_(.+)_(.+)$", Tags: TagSet{Present: []string{"region=$1", "environment=$2"}, Absent: nil}}},
			desiredTags: []string{"asdf", "banana", "environment=testing", "orange", "region=us-southeast"},
			found:       true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, found := getNewTags(tc.label, tc.tags, tc.rules)

			require.Equal(t, tc.found, found)
			require.Equal(t, tc.desiredTags, got)
		})
	}
}
