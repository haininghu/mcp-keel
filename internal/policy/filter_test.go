package policy

import "testing"

func TestLabelFilterMatches(t *testing.T) {
	cases := []struct {
		name   string
		filter LabelFilter
		set    LabelSet
		want   bool
	}{
		{"empty filter passes without labels", LabelFilter{}, LabelSet{}, true},
		{"bare key matches presence", LabelFilter{Require: []string{"noai"}}, labels(map[string]string{"noai": ""}), true},
		{"bare key misses absence", LabelFilter{Require: []string{"noai"}}, labels(map[string]string{"other": "x"}), false},
		{"key=value matches exact", LabelFilter{Require: []string{"team=platform"}}, labels(map[string]string{"team": "platform"}), true},
		{"key=value is case-sensitive", LabelFilter{Require: []string{"team=platform"}}, labels(map[string]string{"team": "Platform"}), false},
		{"require needs all entries", LabelFilter{Require: []string{"a", "b"}}, labels(map[string]string{"a": ""}), false},
		{"exclude present fails", LabelFilter{Exclude: []string{"noai"}}, labels(map[string]string{"noai": ""}), false},
		{"exclude absent passes", LabelFilter{Exclude: []string{"noai"}}, labels(map[string]string{"other": "x"}), true},
		{"exclude wins over require", LabelFilter{Require: []string{"a"}, Exclude: []string{"a"}}, labels(map[string]string{"a": ""}), false},
		{"unknown labels fail closed", LabelFilter{Require: []string{"a"}}, LabelSet{Known: false}, false},
		{"unknown labels fail closed with exclude", LabelFilter{Exclude: []string{"a"}}, LabelSet{Known: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.matches(tc.set); got != tc.want {
				t.Fatalf("LabelFilter%+v.matches(%+v) = %v, want %v", tc.filter, tc.set, got, tc.want)
			}
		})
	}
}

func TestNameFilterMatches(t *testing.T) {
	cases := []struct {
		name   string
		filter NameFilter
		object string
		want   bool
	}{
		{"empty filter passes", NameFilter{}, "", true},
		{"include match", NameFilter{Include: []string{"frontend-*"}}, "frontend-1", true},
		{"include miss", NameFilter{Include: []string{"frontend-*"}}, "backend-1", false},
		{"include is anchored", NameFilter{Include: []string{"test-*"}}, "xtest-a", false},
		{"include needs one of many", NameFilter{Include: []string{"frontend-*", "api-*"}}, "api-1", true},
		{"exclude match fails", NameFilter{Exclude: []string{"*-debug"}}, "frontend-debug", false},
		{"exclude miss passes", NameFilter{Exclude: []string{"*-debug"}}, "frontend-1", true},
		{"exclude wins over include", NameFilter{Include: []string{"frontend-*"}, Exclude: []string{"*-debug"}}, "frontend-debug", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.matches(tc.object); got != tc.want {
				t.Fatalf("NameFilter%+v.matches(%q) = %v, want %v", tc.filter, tc.object, got, tc.want)
			}
		})
	}
}
