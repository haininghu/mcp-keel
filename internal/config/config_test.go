package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/haininghu/mcp-keel/internal/policy"
)

// goodConfig is a minimal but valid configuration used as the base for the
// negative test cases below; each case replaces a single fragment.
const goodConfig = `version: 1
server:
  log_level: info
providers:
  - name: p
    contexts: ["*"]
    rules:
      - namespaces: ["*"]
        effect: allow
        capabilities:
          - core/pods:get
`

func TestParseExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	assertServerDefaults(t, &cfg.Server)
	if got := cfg.Server.AdditionalSensitiveResources; len(got) != 1 || got[0] != "autoscaling/horizontalpodautoscalers" {
		t.Errorf("AdditionalSensitiveResources = %v", got)
	}
	if strings.Contains(cfg.Server.Kubeconfig, "${") {
		t.Errorf("Kubeconfig = %q, want the ${HOME} reference expanded", cfg.Server.Kubeconfig)
	}
	if len(cfg.Providers) != 4 {
		t.Fatalf("len(Providers) = %d, want 4", len(cfg.Providers))
	}

	testClusters := cfg.Providers[0]
	if testClusters.Name != "test-clusters" || testClusters.PolicyRead {
		t.Errorf("provider[0] = %+v", testClusters)
	}
	if want := []string{"*test*", "dev-play-cluster"}; !slices.Equal(testClusters.Contexts, want) {
		t.Errorf("provider[0].Contexts = %v, want %v", testClusters.Contexts, want)
	}
	if len(testClusters.Rules) != 4 {
		t.Fatalf("provider[0] rules = %d, want 4", len(testClusters.Rules))
	}
	if r := testClusters.Rules[0]; r.Effect != policy.EffectDeny || len(r.Capabilities) != 0 {
		t.Errorf("provider[0].rules[0] = %+v, want scope-only deny", r)
	}
	if c := testClusters.Rules[1].Capabilities[0]; !c.Wildcard || !c.VerbWildcard ||
		!slices.Equal(c.Filter.Labels.Require, []string{"noai"}) {
		t.Errorf("provider[0].rules[1].capabilities[0] = %+v", c)
	}
	allow := testClusters.Rules[2].Capabilities
	if len(allow) != 8 {
		t.Fatalf("provider[0].rules[2] capabilities = %d, want 8", len(allow))
	}
	if got := allow[5]; got.Resource != "secrets" || got.Verb != policy.VerbGet || got.Wildcard {
		t.Errorf("allow[5] = %+v, want explicit secrets:get", got)
	}
	if got := allow[6]; got.Resource != "*" || !got.Wildcard || got.VerbWildcard {
		t.Errorf("allow[6] = %+v, want \"*:get\"", got)
	}

	prod := cfg.Providers[1]
	if prod.QPS == nil || *prod.QPS != 50 || prod.Burst == nil || *prod.Burst != 100 {
		t.Errorf("provider[1] overrides = qps %v burst %v", prod.QPS, prod.Burst)
	}
	if prod.RequestTimeout == nil || *prod.RequestTimeout != Duration(60*time.Second) {
		t.Errorf("provider[1].RequestTimeout = %v", prod.RequestTimeout)
	}
	if prod.DiscoveryCacheTTL == nil || *prod.DiscoveryCacheTTL != Duration(5*time.Minute) {
		t.Errorf("provider[1].DiscoveryCacheTTL = %v", prod.DiscoveryCacheTTL)
	}
	if prod.DiscoveryTimeout != nil {
		t.Errorf("provider[1].DiscoveryTimeout = %v, want nil", prod.DiscoveryTimeout)
	}
	if c := prod.Rules[0].Capabilities[0]; c.Resource != "apps/deployments" || !c.VerbWildcard {
		t.Errorf("provider[1].rules[0].capabilities[0] = %+v", c)
	}

	if n := cfg.Providers[2].Rules[1].Namespaces; len(n) != 1 || n[0] != "" {
		t.Errorf("provider[2].rules[1].Namespaces = %v, want the \"\" cluster marker", n)
	}
	if self := cfg.Providers[3]; !self.PolicyRead || len(self.Rules) != 0 {
		t.Errorf("provider[3] = %+v, want policy_read with no rules", self)
	}
}

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte("providers:\n  - name: p\n    contexts: [\"*\"]\n    rules: []\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
	assertServerDefaults(t, &cfg.Server)
	if cfg.Server.NamespaceMarker.Enabled {
		t.Error("NamespaceMarker.Enabled = true, want false")
	}
}

func TestParseStrictUnknownKeys(t *testing.T) {
	cases := map[string]string{
		"top level":         strings.Replace(goodConfig, "version: 1", "version: 1\nfoo: bar", 1),
		"server":            strings.Replace(goodConfig, "log_level: info", "log_level: info\n  foo: bar", 1),
		"provider":          strings.Replace(goodConfig, "contexts: [\"*\"]", "contexts: [\"*\"]\n    foo: bar", 1),
		"rule":              strings.Replace(goodConfig, "effect: allow", "effect: allow\n        foo: bar", 1),
		"capability filter": strings.Replace(goodConfig, "- core/pods:get", "- \"core/pods:get\":\n              filters: {}", 1),
		"labels":            strings.Replace(goodConfig, "- core/pods:get", "- \"core/pods:get\":\n              labels:\n                need: [\"x\"]", 1),
		"names":             strings.Replace(goodConfig, "- core/pods:get", "- \"core/pods:get\":\n              names:\n                want: [\"x\"]", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse() error = nil, want an error for an unknown key")
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	cases := map[string]string{
		"wrong version":            strings.Replace(goodConfig, "version: 1", "version: 2", 1),
		"bad log level":            strings.Replace(goodConfig, "log_level: info", "log_level: verbose", 1),
		"request timeout zero":     strings.Replace(goodConfig, "log_level: info", "log_level: info\n  request_timeout: 0s", 1),
		"discovery cache negative": strings.Replace(goodConfig, "log_level: info", "log_level: info\n  discovery_cache_ttl: -1s", 1),
		"qps zero":                 strings.Replace(goodConfig, "log_level: info", "log_level: info\n  qps: 0", 1),
		"burst zero":               strings.Replace(goodConfig, "log_level: info", "log_level: info\n  burst: 0", 1),
		"max list items zero":      strings.Replace(goodConfig, "log_level: info", "log_level: info\n  max_list_items: 0", 1),
		"max list items too big":   strings.Replace(goodConfig, "log_level: info", "log_level: info\n  max_list_items: 1001", 1),
		"max object bytes zero":    strings.Replace(goodConfig, "log_level: info", "log_level: info\n  max_object_bytes: 0", 1),
		"max response bytes zero":  strings.Replace(goodConfig, "log_level: info", "log_level: info\n  max_response_bytes: 0", 1),
		"no providers":             "version: 1\nserver: {}\n",
		"empty provider name":      strings.Replace(goodConfig, "name: p", "name: \"\"", 1),
		"empty contexts":           strings.Replace(goodConfig, "contexts: [\"*\"]", "contexts: []", 1),
		"bad context glob":         strings.Replace(goodConfig, "contexts: [\"*\"]", "contexts: [\"[bad\"]", 1),
		"missing effect":           strings.Replace(goodConfig, "        effect: allow\n", "", 1),
		"empty namespaces":         strings.Replace(goodConfig, "namespaces: [\"*\"]", "namespaces: []", 1),
		"bad namespace glob":       strings.Replace(goodConfig, "namespaces: [\"*\"]", "namespaces: [\"[bad\"]", 1),
		"allow without capability": strings.Replace(goodConfig, "        capabilities:\n          - core/pods:get\n", "", 1),
		"unknown verb":             strings.Replace(goodConfig, "core/pods:get", "core/pods:watch", 1),
		"wildcard verb on allow":   strings.Replace(goodConfig, "core/pods:get", "\"*:*\"", 1),
		"wildcard resource mixed":  strings.Replace(goodConfig, "core/pods:get", "apps/*:get", 1),
		"uppercase resource":       strings.Replace(goodConfig, "core/pods:get", "core/Pods:get", 1),
		"missing colon":            strings.Replace(goodConfig, "core/pods:get", "corepodsget", 1),
		"empty resource":           strings.Replace(goodConfig, "core/pods:get", "\":get\"", 1),
		"empty label require":      strings.Replace(goodConfig, "- core/pods:get", "- \"core/pods:get\":\n              labels:\n                require: [\"\"]", 1),
		"label required+excluded":  strings.Replace(goodConfig, "- core/pods:get", "- \"core/pods:get\":\n              labels:\n                require: [\"noai\"]\n                exclude: [\"noai\"]", 1),
		"bad names glob": strings.Replace(goodConfig, "- core/pods:get",
			"- \"core/pods:get\":\n              names:\n                include: [\"[\"]", 1),
		"bad namespace marker": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  namespace_marker:\n    enabled: true\n    label: \"bad label\"", 1),
		"sensitive empty": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  additional_sensitive_resources: [\"\"]", 1),
		"sensitive wildcard": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  additional_sensitive_resources: [\"*\"]", 1),
		"sensitive with group wildcard": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  additional_sensitive_resources: [\"apps/*\"]", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want an error\n---\n%s", input)
			}
		})
	}
}

func TestParseValidWildcardsAndDeny(t *testing.T) {
	denyScopeOnly := strings.Replace(goodConfig, "effect: allow", "effect: deny", 1)
	denyScopeOnly = strings.Replace(denyScopeOnly, "        capabilities:\n          - core/pods:get\n", "", 1)
	if _, err := Parse([]byte(denyScopeOnly)); err != nil {
		t.Errorf("scope-only deny: Parse() error = %v", err)
	}

	denyWildcard := strings.Replace(goodConfig, "effect: allow", "effect: deny", 1)
	denyWildcard = strings.Replace(denyWildcard, "        capabilities:\n          - core/pods:get\n",
		"        capabilities:\n          - \"apps/deployments:*\"\n", 1)
	if _, err := Parse([]byte(denyWildcard)); err != nil {
		t.Errorf("wildcard verb on deny: Parse() error = %v", err)
	}
}

func TestDuplicateProvider(t *testing.T) {
	input := strings.Replace(goodConfig, "providers:",
		"providers:\n  - name: p\n    contexts: [\"*\"]\n    rules: []", 1)
	if _, err := Parse([]byte(input)); err == nil {
		t.Fatal("Parse() error = nil, want a duplicate-provider error")
	}
}

func TestProviderOverrides(t *testing.T) {
	input := `version: 1
server:
  qps: 10
  burst: 20
  request_timeout: 15s
  discovery_timeout: 5s
  discovery_cache_ttl: 1m
providers:
  - name: inherited
    contexts: ["*"]
    rules: []
  - name: overridden
    contexts: ["*"]
    rules: []
    qps: 99
    burst: 77
    request_timeout: 45s
    discovery_timeout: 9s
    discovery_cache_ttl: 0s
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Server.DiscoveryCacheTTL != Duration(time.Minute) {
		t.Errorf("server.DiscoveryCacheTTL = %s", cfg.Server.DiscoveryCacheTTL)
	}
	inherited := cfg.Providers[0]
	if inherited.QPS != nil || inherited.Burst != nil || inherited.RequestTimeout != nil ||
		inherited.DiscoveryTimeout != nil || inherited.DiscoveryCacheTTL != nil {
		t.Errorf("inherited provider overrides = %+v, want all nil", inherited)
	}
	overridden := cfg.Providers[1]
	switch {
	case overridden.QPS == nil || *overridden.QPS != 99:
		t.Errorf("QPS = %v", overridden.QPS)
	case overridden.Burst == nil || *overridden.Burst != 77:
		t.Errorf("Burst = %v", overridden.Burst)
	case overridden.RequestTimeout == nil || *overridden.RequestTimeout != Duration(45*time.Second):
		t.Errorf("RequestTimeout = %v", overridden.RequestTimeout)
	case overridden.DiscoveryTimeout == nil || *overridden.DiscoveryTimeout != Duration(9*time.Second):
		t.Errorf("DiscoveryTimeout = %v", overridden.DiscoveryTimeout)
	case overridden.DiscoveryCacheTTL == nil || *overridden.DiscoveryCacheTTL != 0:
		t.Errorf("DiscoveryCacheTTL = %v, want a non-nil explicit zero", overridden.DiscoveryCacheTTL)
	}
}

func TestServerDiscoveryCacheTTLZeroDisables(t *testing.T) {
	input := strings.Replace(goodConfig, "log_level: info", "log_level: info\n  discovery_cache_ttl: 0s", 1)
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Server.DiscoveryCacheTTL != 0 {
		t.Errorf("server.DiscoveryCacheTTL = %s, want explicit zero", cfg.Server.DiscoveryCacheTTL)
	}
}

func TestParseEmpty(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("Parse(nil) error = nil, want an error")
	}
	if _, err := Parse([]byte("version: 1\n---\nversion: 1\n")); err == nil {
		t.Fatal("Parse() with two documents error = nil, want an error")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("Load() missing file error = nil, want an error")
	}
}

func TestExpandPath(t *testing.T) {
	t.Setenv("MCP_KEEL_TEST_DIR", "/srv/kube")
	if got := expandPath("${MCP_KEEL_TEST_DIR}/config"); got != "/srv/kube/config" {
		t.Errorf("expandPath() = %q, want %q", got, "/srv/kube/config")
	}
	if got := expandPath(""); got != "" {
		t.Errorf("expandPath(\"\") = %q, want empty", got)
	}
	if got := expandPath("$MCP_KEEL_TEST_DIR/x"); got != "$MCP_KEEL_TEST_DIR/x" {
		t.Errorf("expandPath() = %q, want the bare $NAME reference untouched", got)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	if got := expandPath("~/.kube/config"); got != filepath.Join(home, ".kube", "config") {
		t.Errorf("expandPath() = %q", got)
	}
}

func assertServerDefaults(t *testing.T, s *ServerConfig) {
	t.Helper()
	if s.Name != defaultName {
		t.Errorf("Name = %q, want %q", s.Name, defaultName)
	}
	if s.LogLevel != LogLevelInfo {
		t.Errorf("LogLevel = %q, want %q", s.LogLevel, LogLevelInfo)
	}
	if s.RequestTimeout != Duration(defaultRequestTimeout) {
		t.Errorf("RequestTimeout = %s", s.RequestTimeout)
	}
	if s.DiscoveryTimeout != Duration(defaultDiscoveryTimeout) {
		t.Errorf("DiscoveryTimeout = %s", s.DiscoveryTimeout)
	}
	if s.DiscoveryCacheTTL != Duration(defaultDiscoveryCacheTTL) {
		t.Errorf("DiscoveryCacheTTL = %s", s.DiscoveryCacheTTL)
	}
	if s.QPS != defaultQPS || s.Burst != defaultBurst {
		t.Errorf("QPS/Burst = %v/%d", s.QPS, s.Burst)
	}
	if s.MaxListItems != defaultMaxListItems || s.MaxObjectBytes != defaultMaxObjectBytes ||
		s.MaxResponseBytes != defaultMaxResponseBytes {
		t.Errorf("max limits = %d/%d/%d", s.MaxListItems, s.MaxObjectBytes, s.MaxResponseBytes)
	}
	if s.NamespaceMarker.Label != defaultNamespaceMarkerLabel {
		t.Errorf("NamespaceMarker.Label = %q", s.NamespaceMarker.Label)
	}
}

// TestCapabilityForms exercises CapabilityGrant.UnmarshalYAML directly, without
// the strict outer decoder, so the parsing shapes are covered in isolation.
func TestCapabilityForms(t *testing.T) {
	var doc struct {
		Caps []CapabilityGrant `yaml:"capabilities"`
	}
	input := `capabilities:
  - core/pods:get
  - "apps/deployments:list"
  - "*:get":
      labels:
        require: ["managed-by=platform"]
        exclude: ["noai"]
      names:
        include: ["frontend-*"]
        exclude: ["*-debug"]
  - "core/pods:get":
      namespace_marker: allow
`
	if err := yaml.Unmarshal([]byte(input), &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(doc.Caps) != 4 {
		t.Fatalf("len(Caps) = %d, want 4", len(doc.Caps))
	}
	scalar := doc.Caps[0]
	if scalar.Resource != "core/pods" || scalar.Verb != policy.VerbGet || scalar.Wildcard || scalar.VerbWildcard {
		t.Errorf("scalar = %+v", scalar)
	}
	filtered := doc.Caps[2]
	if !filtered.Wildcard || filtered.Verb != policy.VerbGet {
		t.Errorf("filtered wildcard = %+v", filtered)
	}
	if !slices.Equal(filtered.Filter.Labels.Require, []string{"managed-by=platform"}) ||
		!slices.Equal(filtered.Filter.Labels.Exclude, []string{"noai"}) {
		t.Errorf("filtered labels = %+v", filtered.Filter.Labels)
	}
	if !slices.Equal(filtered.Filter.Names.Include, []string{"frontend-*"}) ||
		!slices.Equal(filtered.Filter.Names.Exclude, []string{"*-debug"}) {
		t.Errorf("filtered names = %+v", filtered.Filter.Names)
	}
	if exempt := doc.Caps[3]; !exempt.Filter.NamespaceMarkerExempt {
		t.Errorf("namespace_marker = %+v, want exempt", exempt)
	}
}

func TestDurationUnmarshal(t *testing.T) {
	var doc struct {
		D Duration `yaml:"d"`
	}
	if err := yaml.Unmarshal([]byte("d: 1m30s\n"), &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if doc.D != Duration(90*time.Second) {
		t.Errorf("D = %s, want 1m30s", doc.D)
	}
	if err := yaml.Unmarshal([]byte("d: not-a-duration\n"), &doc); err == nil {
		t.Fatal("Unmarshal() error = nil, want a duration error")
	}
}
