package redact

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/haininghu/mcp-keel/internal/policy"
)

// mustBuild builds an engine and fails the test on error.
func mustBuild(t *testing.T, rules ...Rule) *Engine {
	t.Helper()
	engine, err := Build(rules)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return engine
}

// applyText applies text redaction and fails the test on error.
func applyText(t *testing.T, engine *Engine, s string, m Match) string {
	t.Helper()
	got, err := engine.ApplyText(s, m)
	if err != nil {
		t.Fatalf("ApplyText() error = %v", err)
	}
	return got
}

// applyObject applies object redaction and fails the test on error.
func applyObject(t *testing.T, engine *Engine, obj map[string]any, m Match) map[string]any {
	t.Helper()
	got, err := engine.ApplyObject(obj, m)
	if err != nil {
		t.Fatalf("ApplyObject() error = %v", err)
	}
	return got
}

// redactRule returns a rule that replaces the literal "secret" and lets the
// caller set match dimensions.
func redactRule(mutate func(*Rule)) Rule {
	rule := Rule{Replace: []ReplaceOp{{Text: "secret"}}}
	if mutate != nil {
		mutate(&rule)
	}
	return rule
}

func TestEngineMatching(t *testing.T) {
	pods := policy.Resource{Name: "pods"}
	deployments := policy.Resource{Name: "deployments"}
	appsDeployments := policy.Resource{Group: "apps", Name: "deployments"}
	namespaced := Match{
		Resource:   pods,
		Namespace:  "team-a",
		Namespaced: true,
		Name:       "web-1",
		Labels: policy.LabelSet{
			Known:  true,
			Values: map[string]string{"team": "platform", "tier": "frontend"},
		},
	}
	clusterScoped := Match{
		Resource:   policy.Resource{Name: "nodes"},
		Namespaced: false,
		Name:       "node-1",
		Labels:     policy.LabelSet{Known: true, Values: map[string]string{}},
	}
	unknownLabels := namespaced
	unknownLabels.Labels = policy.LabelSet{}

	cases := []struct {
		name  string
		rule  Rule
		match Match
		want  string
	}{
		{"empty rule matches everything", redactRule(nil), namespaced, "[REDACTED]"},
		{"resource matches", redactRule(func(r *Rule) {
			r.Resources = []policy.Resource{pods}
		}), namespaced, "[REDACTED]"},
		{"resource name mismatch", redactRule(func(r *Rule) {
			r.Resources = []policy.Resource{deployments}
		}), namespaced, "secret"},
		{"resource group mismatch", redactRule(func(r *Rule) {
			r.Resources = []policy.Resource{appsDeployments}
		}), namespaced, "secret"},
		{"resource group and name match", redactRule(func(r *Rule) {
			r.Resources = []policy.Resource{appsDeployments}
		}), Match{Resource: appsDeployments, Namespaced: true, Namespace: "team-a", Name: "web"}, "[REDACTED]"},
		{"namespace glob matches", redactRule(func(r *Rule) {
			r.Namespaces = []string{"team-*"}
		}), namespaced, "[REDACTED]"},
		{"namespace glob misses", redactRule(func(r *Rule) {
			r.Namespaces = []string{"prod-*"}
		}), namespaced, "secret"},
		{"cluster marker does not match namespaced", redactRule(func(r *Rule) {
			r.Namespaces = []string{""}
		}), namespaced, "secret"},
		{"cluster marker matches cluster-scoped", redactRule(func(r *Rule) {
			r.Namespaces = []string{""}
		}), clusterScoped, "[REDACTED]"},
		{"namespace glob does not match cluster-scoped", redactRule(func(r *Rule) {
			r.Namespaces = []string{"*"}
		}), clusterScoped, "secret"},
		{"namespace marker with empty namespaced name", redactRule(func(r *Rule) {
			r.Namespaces = []string{""}
		}), Match{Resource: pods, Namespaced: true, Namespace: ""}, "secret"},
		{"name glob matches", redactRule(func(r *Rule) {
			r.Names = []string{"web-*"}
		}), namespaced, "[REDACTED]"},
		{"name glob misses", redactRule(func(r *Rule) {
			r.Names = []string{"api-*"}
		}), namespaced, "secret"},
		{"doublestar name glob matches", redactRule(func(r *Rule) {
			r.Names = []string{"**"}
		}), namespaced, "[REDACTED]"},
		{"label require passes", redactRule(func(r *Rule) {
			r.Labels = policy.LabelFilter{Require: []string{"team=platform"}}
		}), namespaced, "[REDACTED]"},
		{"label require fails", redactRule(func(r *Rule) {
			r.Labels = policy.LabelFilter{Require: []string{"team=other"}}
		}), namespaced, "secret"},
		{"label exclude fails", redactRule(func(r *Rule) {
			r.Labels = policy.LabelFilter{Exclude: []string{"tier"}}
		}), namespaced, "secret"},
		{"unknown labels fail closed", redactRule(func(r *Rule) {
			r.Labels = policy.LabelFilter{Require: []string{"team"}}
		}), unknownLabels, "secret"},
		{"all dimensions must match", redactRule(func(r *Rule) {
			r.Resources = []policy.Resource{pods}
			r.Namespaces = []string{"team-*"}
			r.Names = []string{"api-*"}
		}), namespaced, "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := mustBuild(t, tc.rule)
			if got := applyText(t, engine, "secret", tc.match); got != tc.want {
				t.Fatalf("ApplyText() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestApplyObjectFields(t *testing.T) {
	containers := func() []any {
		return []any{
			map[string]any{
				"name":  "web",
				"env":   "SECRET",
				"image": "nginx",
			},
			map[string]any{
				"name":  "api",
				"env":   "KEEP",
				"image": "api",
			},
		}
	}
	cases := []struct {
		name   string
		fields []FieldOp
		in     map[string]any
		want   map[string]any
	}{
		{
			name:   "remove bare key",
			fields: []FieldOp{{Path: "a", Action: ActionRemove}},
			in:     map[string]any{"a": "x", "b": "y"},
			want:   map[string]any{"b": "y"},
		},
		{
			name:   "remove quoted key with dot and slash",
			fields: []FieldOp{{Path: `metadata.annotations["a.b/c"]`, Action: ActionRemove}},
			in: map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{"a.b/c": "v", "keep": "k"},
				},
			},
			want: map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{"keep": "k"},
				},
			},
		},
		{
			name:   "remove wildcard clears array",
			fields: []FieldOp{{Path: "items[*]", Action: ActionRemove}},
			in:     map[string]any{"items": []any{"a", "b", "c"}},
			want:   map[string]any{"items": []any{}},
		},
		{
			name:   "remove index",
			fields: []FieldOp{{Path: "items[1]", Action: ActionRemove}},
			in:     map[string]any{"items": []any{"a", "b", "c"}},
			want:   map[string]any{"items": []any{"a", "c"}},
		},
		{
			name:   "remove predicate elements",
			fields: []FieldOp{{Path: "items[name=web]", Action: ActionRemove}},
			in: map[string]any{
				"items": []any{
					map[string]any{"name": "web", "v": 1},
					map[string]any{"name": "api", "v": 2},
					map[string]any{"name": "web", "v": 3},
				},
			},
			want: map[string]any{
				"items": []any{map[string]any{"name": "api", "v": 2}},
			},
		},
		{
			name:   "remove predicate terminal key",
			fields: []FieldOp{{Path: "spec.containers[name=web].env", Action: ActionRemove}},
			in:     map[string]any{"spec": map[string]any{"containers": containers()}},
			want: map[string]any{"spec": map[string]any{"containers": []any{
				map[string]any{"name": "web", "image": "nginx"},
				map[string]any{"name": "api", "env": "KEEP", "image": "api"},
			}}},
		},
		{
			name: "remove parent then child",
			fields: []FieldOp{
				{Path: "a", Action: ActionRemove},
				{Path: "a.b", Action: ActionRemove},
			},
			in:   map[string]any{"a": map[string]any{"b": "x"}},
			want: map[string]any{},
		},
		{
			name:   "replace string",
			fields: []FieldOp{{Path: "a", Action: ActionReplace}},
			in:     map[string]any{"a": "secret", "b": "keep"},
			want:   map[string]any{"a": "[REDACTED]", "b": "keep"},
		},
		{
			name:   "replace with custom marker",
			fields: []FieldOp{{Path: "a", Action: ActionReplace, Marker: "***"}},
			in:     map[string]any{"a": "secret"},
			want:   map[string]any{"a": "***"},
		},
		{
			name:   "replace non-string is no-op",
			fields: []FieldOp{{Path: "a", Action: ActionReplace}},
			in:     map[string]any{"a": map[string]any{"b": 1}},
			want:   map[string]any{"a": map[string]any{"b": 1}},
		},
		{
			name:   "replace missing path is no-op",
			fields: []FieldOp{{Path: "missing", Action: ActionReplace}},
			in:     map[string]any{"a": "secret"},
			want:   map[string]any{"a": "secret"},
		},
		{
			name:   "replace wildcard strings",
			fields: []FieldOp{{Path: "items[*]", Action: ActionReplace}},
			in:     map[string]any{"items": []any{"a", "b", 1}},
			want:   map[string]any{"items": []any{"[REDACTED]", "[REDACTED]", 1}},
		},
		{
			name:   "replace index string",
			fields: []FieldOp{{Path: "items[1]", Action: ActionReplace}},
			in:     map[string]any{"items": []any{"a", "b"}},
			want:   map[string]any{"items": []any{"a", "[REDACTED]"}},
		},
		{
			name:   "index on map is no-op",
			fields: []FieldOp{{Path: "a[0]", Action: ActionRemove}},
			in:     map[string]any{"a": map[string]any{"0": "x"}},
			want:   map[string]any{"a": map[string]any{"0": "x"}},
		},
		{
			name:   "missing intermediate key is no-op",
			fields: []FieldOp{{Path: "a.b.c", Action: ActionRemove}},
			in:     map[string]any{"a": map[string]any{"x": "y"}},
			want:   map[string]any{"a": map[string]any{"x": "y"}},
		},
		{
			name:   "replace predicate element is no-op",
			fields: []FieldOp{{Path: "items[name=web]", Action: ActionReplace}},
			in:     map[string]any{"items": []any{map[string]any{"name": "web"}}},
			want:   map[string]any{"items": []any{map[string]any{"name": "web"}}},
		},
		{
			name: "replace nested wildcard predicate path",
			fields: []FieldOp{{
				Path:   "spec.containers[*].env[name=TOKEN].value",
				Action: ActionReplace,
			}},
			in: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name": "web",
							"env": []any{
								map[string]any{"name": "TOKEN", "value": "secret"},
								map[string]any{"name": "MODE", "value": "prod"},
							},
						},
						map[string]any{
							"name": "api",
							"env": []any{
								map[string]any{"name": "TOKEN", "value": "other"},
							},
						},
					},
				},
			},
			want: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name": "web",
							"env": []any{
								map[string]any{"name": "TOKEN", "value": "[REDACTED]"},
								map[string]any{"name": "MODE", "value": "prod"},
							},
						},
						map[string]any{
							"name": "api",
							"env": []any{
								map[string]any{"name": "TOKEN", "value": "[REDACTED]"},
							},
						},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := mustBuild(t, Rule{Fields: tc.fields})
			if got := applyObject(t, engine, tc.in, Match{}); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ApplyObject() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestApplyObjectDoesNotMutateInput(t *testing.T) {
	obj := map[string]any{
		"metadata": map[string]any{"name": "web"},
		"items":    []any{"token", map[string]any{"v": "token"}},
	}
	original := map[string]any{
		"metadata": map[string]any{"name": "web"},
		"items":    []any{"token", map[string]any{"v": "token"}},
	}
	engine := mustBuild(t, Rule{Replace: []ReplaceOp{{Text: "token"}}})
	got := applyObject(t, engine, obj, Match{})
	if !reflect.DeepEqual(obj, original) {
		t.Fatalf("ApplyObject() mutated the input: %#v", obj)
	}
	if reflect.DeepEqual(got, obj) {
		t.Fatalf("ApplyObject() returned unredacted content: %#v", got)
	}
	items, ok := got["items"].([]any)
	if !ok || len(items) < 2 {
		t.Fatalf("ApplyObject() result has an unexpected shape: %#v", got)
	}
	entry, ok := items[1].(map[string]any)
	if !ok {
		t.Fatalf("ApplyObject() result has an unexpected shape: %#v", got)
	}
	entry["v"] = "changed"
	inputItems, ok := obj["items"].([]any)
	if !ok || len(inputItems) < 2 {
		t.Fatalf("input has an unexpected shape: %#v", obj)
	}
	inputEntry, ok := inputItems[1].(map[string]any)
	if !ok {
		t.Fatalf("input has an unexpected shape: %#v", obj)
	}
	if inputEntry["v"] != "token" {
		t.Fatalf("ApplyObject() result shares state with the input")
	}
}

func TestApplyTextReplace(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		in    string
		want  string
	}{
		{
			name:  "literal single occurrence",
			rules: []Rule{{Replace: []ReplaceOp{{Text: "token-abc"}}}},
			in:    "the token is token-abc",
			want:  "the token is [REDACTED]",
		},
		{
			name:  "literal multiple occurrences",
			rules: []Rule{{Replace: []ReplaceOp{{Text: "token"}}}},
			in:    "token token",
			want:  "[REDACTED] [REDACTED]",
		},
		{
			name:  "RE2 pattern",
			rules: []Rule{{Replace: []ReplaceOp{{Pattern: `\b\d{3}-\d{2}-\d{4}\b`}}}},
			in:    "ssn 123-45-6789 and 987-65-4321",
			want:  "ssn [REDACTED] and [REDACTED]",
		},
		{
			name:  "marker override",
			rules: []Rule{{Replace: []ReplaceOp{{Text: "secret", Marker: "[X]"}}}},
			in:    "a secret",
			want:  "a [X]",
		},
		{
			name: "overlapping matches first rule wins",
			rules: []Rule{
				{Replace: []ReplaceOp{{Text: "abcdef", Marker: "A"}}},
				{Replace: []ReplaceOp{{Text: "cdefgh", Marker: "B"}}},
			},
			in:   "abcdefgh",
			want: "AB",
		},
		{
			name: "no cascade over an inserted marker",
			rules: []Rule{
				{Replace: []ReplaceOp{{Text: "secret"}}},
				{Replace: []ReplaceOp{{Text: "[REDACTED]", Marker: "X"}}},
			},
			in:   "secret",
			want: "[REDACTED]",
		},
		{
			name: "union of matching rules",
			rules: []Rule{
				{Replace: []ReplaceOp{{Text: "alpha", Marker: "A"}}},
				{Replace: []ReplaceOp{{Text: "beta", Marker: "B"}}},
			},
			in:   "alpha beta",
			want: "A B",
		},
		{
			name:  "no match is unchanged",
			rules: []Rule{{Replace: []ReplaceOp{{Text: "secret"}}}},
			in:    "nothing to see",
			want:  "nothing to see",
		},
		{
			name:  "empty string",
			rules: []Rule{{Replace: []ReplaceOp{{Text: "secret"}}}},
			in:    "",
			want:  "",
		},
		{
			name:  "fields-only rule leaves text unchanged",
			rules: []Rule{{Fields: []FieldOp{{Path: "a", Action: ActionRemove}}}},
			in:    "secret",
			want:  "secret",
		},
		{
			name:  "non-matching rule leaves text unchanged",
			rules: []Rule{redactRule(func(r *Rule) { r.Namespaces = []string{"prod-*"} })},
			in:    "secret",
			want:  "secret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := mustBuild(t, tc.rules...)
			m := Match{Resource: policy.Resource{Name: "pods"}, Namespace: "team-a", Namespaced: true}
			if got := applyText(t, engine, tc.in, m); got != tc.want {
				t.Fatalf("ApplyText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestApplyTextPreservesLineEndings(t *testing.T) {
	engine := mustBuild(t, Rule{Replace: []ReplaceOp{{Text: "token"}}})
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "multi-line log",
			in:   "first token\nsecond token\n",
			want: "first [REDACTED]\nsecond [REDACTED]\n",
		},
		{
			name: "CRLF preserved",
			in:   "a\r\ntoken\r\nb",
			want: "a\r\n[REDACTED]\r\nb",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := applyText(t, engine, tc.in, Match{}); got != tc.want {
				t.Fatalf("ApplyText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestApplyObjectPhases(t *testing.T) {
	fields := Rule{Fields: []FieldOp{{Path: "items[name=secret]", Action: ActionRemove}}}
	replace := Rule{Replace: []ReplaceOp{{Text: "secret", Marker: "TEXT"}}}
	for _, tc := range []struct {
		name  string
		rules []Rule
	}{
		{"fields rule first", []Rule{fields, replace}},
		{"replace rule first", []Rule{replace, fields}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := mustBuild(t, tc.rules...)
			obj := map[string]any{"items": []any{map[string]any{"name": "secret", "value": "x"}}}
			want := map[string]any{"items": []any{}}
			if got := applyObject(t, engine, obj, Match{}); !reflect.DeepEqual(got, want) {
				t.Fatalf("ApplyObject() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestApplyObjectReplaceUnion(t *testing.T) {
	engine := mustBuild(t,
		Rule{Replace: []ReplaceOp{{Text: "alpha", Marker: "A"}}},
		Rule{Replace: []ReplaceOp{{Text: "beta", Marker: "B"}}},
	)
	obj := map[string]any{"a": "alpha beta", "b": "beta"}
	want := map[string]any{"a": "A B", "b": "B"}
	if got := applyObject(t, engine, obj, Match{}); !reflect.DeepEqual(got, want) {
		t.Fatalf("ApplyObject() = %#v, want %#v", got, want)
	}
}

// nestedObject builds an object with depth levels of maps and a "secret" leaf
// at that depth.
func nestedObject(depth int) map[string]any {
	root := map[string]any{}
	current := root
	for i := 1; i < depth; i++ {
		next := map[string]any{}
		current["n"] = next
		current = next
	}
	current["leaf"] = "secret"
	return root
}

func TestApplyObjectDepthCap(t *testing.T) {
	engine := mustBuild(t, Rule{Replace: []ReplaceOp{{Text: "secret"}}})
	if _, err := engine.ApplyObject(nestedObject(MaxDepth), Match{}); err != nil {
		t.Fatalf("ApplyObject(depth %d) error = %v, want nil", MaxDepth, err)
	}
	got, err := engine.ApplyObject(nestedObject(MaxDepth+1), Match{})
	if !errors.Is(err, ErrCapBreached) {
		t.Fatalf("ApplyObject(depth %d) error = %v, want ErrCapBreached", MaxDepth+1, err)
	}
	if got != nil {
		t.Fatalf("ApplyObject() returned content on a cap breach: %#v", got)
	}
}

func TestApplyObjectWorkBytesCap(t *testing.T) {
	engine := mustBuild(t, Rule{Replace: []ReplaceOp{{Text: "needle"}}})
	obj := map[string]any{"a": strings.Repeat("a", MaxWorkBytes)}
	if _, err := engine.ApplyObject(obj, Match{}); err != nil {
		t.Fatalf("ApplyObject() at MaxWorkBytes error = %v, want nil", err)
	}
	obj["a"] = strings.Repeat("a", MaxWorkBytes+1)
	got, err := engine.ApplyObject(obj, Match{})
	if !errors.Is(err, ErrCapBreached) {
		t.Fatalf("ApplyObject() error = %v, want ErrCapBreached", err)
	}
	if got != nil {
		t.Fatalf("ApplyObject() returned content on a cap breach: %#v", got)
	}
}

func TestApplyTextWorkBytesCap(t *testing.T) {
	engine := mustBuild(t, Rule{Replace: []ReplaceOp{{Text: "needle"}}})
	if got := applyText(t, engine, strings.Repeat("a", MaxWorkBytes), Match{}); len(got) != MaxWorkBytes {
		t.Fatalf("ApplyText() at MaxWorkBytes returned %d bytes, want %d", len(got), MaxWorkBytes)
	}
	got, err := engine.ApplyText(strings.Repeat("a", MaxWorkBytes+1), Match{})
	if !errors.Is(err, ErrCapBreached) {
		t.Fatalf("ApplyText() error = %v, want ErrCapBreached", err)
	}
	if got != "" {
		t.Fatalf("ApplyText() returned content on a cap breach: %q", got)
	}
}

func TestBuildDefaultMarker(t *testing.T) {
	engine := mustBuild(t, Rule{
		Fields:  []FieldOp{{Path: "field", Action: ActionReplace}},
		Replace: []ReplaceOp{{Text: "secret"}},
	})
	got := applyObject(t, engine, map[string]any{"field": "x", "text": "secret"}, Match{})
	want := map[string]any{"field": DefaultMarker, "text": DefaultMarker}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ApplyObject() = %#v, want %#v", got, want)
	}
}

func TestBuildErrors(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
	}{
		{
			name: "empty path",
			rule: Rule{Fields: []FieldOp{{Path: "", Action: ActionRemove}}},
		},
		{
			name: "unterminated bracket",
			rule: Rule{Fields: []FieldOp{{Path: "a[", Action: ActionRemove}}},
		},
		{
			name: "empty bracket",
			rule: Rule{Fields: []FieldOp{{Path: "a[]", Action: ActionRemove}}},
		},
		{
			name: "closing bracket in predicate value",
			rule: Rule{Fields: []FieldOp{{Path: "a[name=x]y]", Action: ActionRemove}}},
		},
		{
			name: "invalid action",
			rule: Rule{Fields: []FieldOp{{Path: "a", Action: "drop"}}},
		},
		{
			name: "invalid RE2 pattern",
			rule: Rule{Replace: []ReplaceOp{{Pattern: "("}}},
		},
		{
			name: "text and pattern",
			rule: Rule{Replace: []ReplaceOp{{Text: "a", Pattern: "b"}}},
		},
		{
			name: "neither text nor pattern",
			rule: Rule{Replace: []ReplaceOp{{Marker: "[X]"}}},
		},
		{
			name: "invalid namespace glob",
			rule: Rule{Namespaces: []string{"["}, Replace: []ReplaceOp{{Text: "a"}}},
		},
		{
			name: "invalid name glob",
			rule: Rule{Names: []string{"["}, Replace: []ReplaceOp{{Text: "a"}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build([]Rule{tc.rule}); err == nil {
				t.Fatalf("Build() error = nil, want an error")
			}
		})
	}
}

func TestBuildAcceptsValidRules(t *testing.T) {
	rules := []Rule{
		{},
		{
			Resources:  []policy.Resource{{Group: "apps", Name: "deployments"}},
			Namespaces: []string{"team-*", ""},
			Names:      []string{"web-*"},
			Labels:     policy.LabelFilter{Require: []string{"confidential"}},
			Fields: []FieldOp{
				{Path: "data", Action: ActionRemove},
				{Path: `metadata.annotations["a.b/c"]`, Action: ActionRemove},
				{Path: "spec.containers[*].env[name=TOKEN].value", Action: ActionReplace},
				{Path: "items[0].value", Action: ActionReplace, Marker: "[X]"},
			},
			Replace: []ReplaceOp{
				{Text: "token", Marker: "[T]"},
				{Pattern: `\b\d{1,3}(\.\d{1,3}){3}\b`, Marker: "[IP]"},
			},
		},
	}
	if _, err := Build(rules); err != nil {
		t.Fatalf("Build() error = %v", err)
	}
}
