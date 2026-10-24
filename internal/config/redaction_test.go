package config

import (
	"path/filepath"
	"slices"
	"testing"
)

// redactionRuleConfig wraps a single redaction rule (indented six spaces) in a
// minimal valid provider.
func redactionRuleConfig(rule string) string {
	return "version: 1\nserver: {}\nproviders:\n  - name: p\n    contexts: [\"*\"]\n    rules: []\n    redactions:\n" + rule
}

func TestParseRedactionsValid(t *testing.T) {
	cases := map[string]string{
		"fields only":  "      - fields:\n          - { path: data, action: remove }\n",
		"replace only": "      - replace:\n          - { text: \"token-abc\" }\n",
		"empty dimensions": `      - resources: []
        namespaces: []
        names: []
        fields:
          - { path: metadata.annotations, action: remove }
`,
		"all dimensions": `      - resources: ["core/secrets", "core/pods/log"]
        namespaces: ["test-*", ""]
        names: ["app-*"]
        labels:
          require: ["confidential"]
          exclude: ["public"]
        fields:
          - { path: "spec.containers[*].env[name=TOKEN].value", action: replace }
        replace:
          - { text: "my-static-token" }
          - { pattern: '\b\d{1,3}(\.\d{1,3}){3}\b', marker: "[IP]" }
`,
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := Parse([]byte(redactionRuleConfig(rule)))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got := len(cfg.Providers[0].Redactions); got != 1 {
				t.Fatalf("len(Redactions) = %d, want 1", got)
			}
		})
	}
}

func TestParseRedactionsShape(t *testing.T) {
	cfg, err := Parse([]byte(redactionRuleConfig(`      - resources: ["core/secrets"]
        namespaces: ["test-*", ""]
        labels:
          require: ["confidential"]
        fields:
          - { path: data, action: remove, marker: "[X]" }
        replace:
          - { text: "token" }
          - { pattern: "ip", marker: "[IP]" }
`)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	rule := cfg.Providers[0].Redactions[0]
	if !slices.Equal(rule.Resources, []string{"core/secrets"}) {
		t.Errorf("Resources = %v", rule.Resources)
	}
	if !slices.Equal(rule.Namespaces, []string{"test-*", ""}) {
		t.Errorf("Namespaces = %v", rule.Namespaces)
	}
	if !slices.Equal(rule.Labels.Require, []string{"confidential"}) {
		t.Errorf("Labels.Require = %v", rule.Labels.Require)
	}
	if f := rule.Fields[0]; f.Path != "data" || f.Action != fieldActionRemove ||
		f.Marker == nil || *f.Marker != "[X]" {
		t.Errorf("Fields[0] = %+v", f)
	}
	if r := rule.Replace[0]; r.Text != "token" || r.Pattern != "" || r.Marker != nil {
		t.Errorf("Replace[0] = %+v", r)
	}
	if r := rule.Replace[1]; r.Pattern != "ip" || r.Marker == nil || *r.Marker != "[IP]" {
		t.Errorf("Replace[1] = %+v", r)
	}
}

func TestParseExampleRedactions(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reds := cfg.Providers[0].Redactions
	if len(reds) != 2 {
		t.Fatalf("len(provider[0].Redactions) = %d, want 2", len(reds))
	}

	secrets := reds[0]
	if !slices.Equal(secrets.Resources, []string{"core/secrets"}) || len(secrets.Fields) != 3 {
		t.Errorf("redactions[0] = %+v", secrets)
	}
	if f := secrets.Fields[0]; f.Path != "data" || f.Action != fieldActionRemove || f.Marker != nil {
		t.Errorf("redactions[0].fields[0] = %+v", f)
	}

	pods := reds[1]
	if !slices.Equal(pods.Resources, []string{"core/pods"}) ||
		!slices.Equal(pods.Namespaces, []string{"test-*"}) ||
		!slices.Equal(pods.Labels.Require, []string{"confidential"}) {
		t.Errorf("redactions[1] = %+v", pods)
	}
	if f := pods.Fields[0]; f.Path != "spec.containers[*].env[name=TOKEN].value" ||
		f.Action != fieldActionReplace || f.Marker != nil {
		t.Errorf("redactions[1].fields[0] = %+v", f)
	}
	if r := pods.Replace[0]; r.Text != "my-static-token" || r.Marker != nil {
		t.Errorf("redactions[1].replace[0] = %+v", r)
	}
	if r := pods.Replace[1]; r.Pattern == "" || r.Marker == nil || *r.Marker != "[IP]" {
		t.Errorf("redactions[1].replace[1] = %+v", r)
	}
}

func TestParseRedactionsInvalid(t *testing.T) {
	cases := map[string]string{
		"unknown rule key": "      - bogus: 1\n        fields:\n          - { path: data, action: remove }\n",
		"unknown field key": "      - fields:\n" +
			"          - { path: data, action: remove, foo: 1 }\n",
		"unknown replace key": "      - replace:\n" +
			"          - { text: a, foo: 1 }\n",
		"resource wildcard": "      - resources: [\"*\"]\n" +
			"        fields:\n          - { path: data, action: remove }\n",
		"empty resource": "      - resources: [\"\"]\n" +
			"        fields:\n          - { path: data, action: remove }\n",
		"empty path":           "      - fields:\n          - { path: \"\", action: remove }\n",
		"missing action":       "      - fields:\n          - { path: data }\n",
		"invalid action":       "      - fields:\n          - { path: data, action: drop }\n",
		"text and pattern":     "      - replace:\n          - { text: a, pattern: b }\n",
		"neither text pattern": "      - replace:\n          - { marker: \"[X]\" }\n",
		"empty text":           "      - replace:\n          - { text: \"\" }\n",
		"invalid RE2":          "      - replace:\n          - { pattern: \"[\" }\n",
		"empty field marker": "      - fields:\n" +
			"          - { path: data, action: remove, marker: \"\" }\n",
		"empty replace marker": "      - replace:\n" +
			"          - { text: a, marker: \"\" }\n",
		"rule without action": "      - resources: [\"core/pods\"]\n",
		"bad namespace glob": "      - namespaces: [\"[bad\"]\n" +
			"        fields:\n          - { path: data, action: remove }\n",
		"bad name glob": "      - names: [\"[bad\"]\n" +
			"        fields:\n          - { path: data, action: remove }\n",
		"label overlap": "      - labels:\n          require: [\"noai\"]\n          exclude: [\"noai\"]\n" +
			"        fields:\n          - { path: data, action: remove }\n",
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(redactionRuleConfig(rule))); err == nil {
				t.Fatalf("Parse() error = nil, want an error\n---\n%s", rule)
			}
		})
	}
}
