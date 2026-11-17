package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
)

// strPtr returns a pointer to s for marker overrides.
func strPtr(s string) *string {
	return &s
}

// labeledPod builds a pod fixture with the given labels.
func labeledPod(name, namespace string, labels map[string]string) *unstructured.Unstructured {
	return pod(name, namespace, labels)
}

// getObject decodes the object of a get response.
func getObject(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	object, ok := out["object"].(map[string]any)
	if !ok {
		t.Fatalf("object = %T, want map", out["object"])
	}
	return object
}

func TestGetAppliesFieldAndReplaceRedactions(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"pods"},
		Fields:    []config.FieldRedaction{{Path: "spec.containers", Action: "remove"}},
		Replace:   []config.ReplaceRedaction{{Text: "web", Marker: strPtr("***")}},
	}}
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "web")
	cluster.getObj.SetLabels(map[string]string{"app": "web"})
	env := newTestEnv(t, cfg, cluster)

	object := getObject(t, env.callOK("get", getArgs("pods", "ns", "web-1")))
	spec, ok := object["spec"].(map[string]any)
	if !ok {
		t.Fatalf("spec = %T, want map", object["spec"])
	}
	if _, present := spec["containers"]; present {
		t.Error("spec.containers was not removed")
	}
	metadata, _ := object["metadata"].(map[string]any)
	if metadata["name"] != "***-1" {
		t.Errorf("metadata.name = %v, want the replaced name", metadata["name"])
	}
	labels, _ := metadata["labels"].(map[string]any)
	if labels["app"] != "***" {
		t.Errorf("labels.app = %v, want ***", labels["app"])
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal object: %v", err)
	}
	if strings.Contains(string(encoded), "web") {
		t.Errorf("the literal survived redaction: %s", encoded)
	}
}

func TestGetWithoutRedactionsIsUnchanged(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	env := newTestEnv(t, cfg, cluster)

	object := getObject(t, env.callOK("get", getArgs("pods", "ns", "web-1")))
	spec, _ := object["spec"].(map[string]any)
	containers, _ := spec["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("containers = %v, want the stored content", spec["containers"])
	}
	if metadata, _ := object["metadata"].(map[string]any); metadata["name"] != "web-1" {
		t.Errorf("metadata.name = %v, want web-1", metadata["name"])
	}
	if cluster.canonicalCalls != 2 {
		t.Errorf("canonicalCalls = %d, want 2 (resource + no redaction resources)", cluster.canonicalCalls)
	}
}

func TestListRedactsEachItem(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbList))})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"pods"},
		Replace:   []config.ReplaceRedaction{{Text: "db"}},
	}}
	cluster := baseCluster()
	cluster.listItems = []unstructured.Unstructured{
		*pod("web-1", "ns", map[string]string{"app": "web"}),
		*pod("db-1", "ns", map[string]string{"app": "db"}),
	}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	})
	items, _ := out["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	for _, item := range items {
		object, _ := item.(map[string]any)
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if strings.Contains(name, "db") {
			t.Errorf("item %q was not redacted", name)
		}
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v, want false", out["truncated"])
	}
}

func TestListDropsItemOnRedactionCapBreach(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbList))})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"pods"},
		Replace:   []config.ReplaceRedaction{{Pattern: "x"}},
	}}
	cluster := baseCluster()
	small := pod("small", "ns", nil)
	deep := pod("deep", "ns", nil)
	deep.Object["data"] = nestedObject(70)
	cluster.listItems = []unstructured.Unstructured{*small, *deep}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	})
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %d, want the small item only", len(items))
	}
	metadata, _ := items[0].(map[string]any)["metadata"].(map[string]any)
	if metadata["name"] != "small" {
		t.Errorf("returned item = %v, want small", metadata["name"])
	}
	if out["truncated"] != true {
		t.Errorf("truncated = %v, want true for a dropped item", out["truncated"])
	}
	if _, present := out["hidden"]; present {
		t.Error("hidden count must never be returned")
	}
}

// nestedObject builds a JSON object nested depth levels deep, which breaches the
// redaction engine's depth cap.
func nestedObject(depth int) map[string]any {
	value := map[string]any{"leaf": "x"}
	for i := 0; i < depth; i++ {
		value = map[string]any{"nested": value}
	}
	return value
}

func TestRedactionUnresolvableResourceIsSkipped(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Providers[0].Redactions = []config.RedactionConfig{
		{
			Resources: []string{"widgets"},
			Replace:   []config.ReplaceRedaction{{Text: "web", Marker: strPtr("GONE")}},
		},
		{
			Resources: []string{"widgets", "pods"},
			Replace:   []config.ReplaceRedaction{{Text: "db", Marker: strPtr("###")}},
		},
	}
	cluster := baseCluster()
	cluster.getObj = labeledPod("web-1", "ns", map[string]string{"app": "web", "tier": "db"})
	env := newTestEnv(t, cfg, cluster)

	object := getObject(t, env.callOK("get", getArgs("pods", "ns", "web-1")))
	metadata, _ := object["metadata"].(map[string]any)
	if metadata["name"] != "web-1" {
		t.Errorf("metadata.name = %v, want web-1 (the dropped rule must not apply)", metadata["name"])
	}
	labels, _ := metadata["labels"].(map[string]any)
	if labels["app"] != "web" {
		t.Errorf("labels.app = %v, want web", labels["app"])
	}
	if labels["tier"] != "###" {
		t.Errorf("labels.tier = %v, want ### from the surviving rule", labels["tier"])
	}

	env.srv.policyMu.Lock()
	cached := len(env.srv.redactions)
	env.srv.policyMu.Unlock()
	if cached != 1 {
		t.Fatalf("cached redaction engines = %d, want 1", cached)
	}
}

func TestListConfiguredRulesExposesRedactionStructureWithoutText(t *testing.T) {
	cfg := &config.Config{
		Version: 1,
		Server:  config.ServerConfig{Name: "test", MaxListItems: 500, MaxObjectBytes: 1 << 20, MaxResponseBytes: 1 << 20},
		Providers: []config.ProviderConfig{{
			Name:       "visible",
			Contexts:   []string{"*"},
			PolicyRead: true,
			Rules:      []config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))},
			Redactions: []config.RedactionConfig{{
				Resources:  []string{"pods"},
				Namespaces: []string{"ns-*"},
				Names:      []string{"web-*"},
				Labels:     policy.LabelFilter{Require: []string{"app=web"}},
				Fields: []config.FieldRedaction{{
					Path: "spec.containers[*].env", Action: "remove", Marker: strPtr("<hidden>"),
				}},
				Replace: []config.ReplaceRedaction{
					{Text: "super-secret-token"},
					{Pattern: `tok-[0-9]+`, Marker: strPtr("[TOKEN]")},
				},
			}},
		}},
	}
	env := newTestEnv(t, cfg, baseCluster())

	text := resultText(t, env.call("list_configured_rules", nil))
	if strings.Contains(text, "super-secret-token") {
		t.Fatalf("list_configured_rules leaked the literal replace text: %s", text)
	}
	out := decodeJSON(t, text)
	providers, _ := out["providers"].([]any)
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(providers))
	}
	redactions, _ := providers[0].(map[string]any)["redactions"].([]any)
	if len(redactions) != 1 {
		t.Fatalf("redactions = %v, want 1", redactions)
	}
	rule, _ := redactions[0].(map[string]any)
	if namespaces, _ := rule["namespaces"].([]any); len(namespaces) != 1 || namespaces[0] != "ns-*" {
		t.Errorf("namespaces = %v", rule["namespaces"])
	}
	fields, _ := rule["fields"].([]any)
	if len(fields) != 1 {
		t.Fatalf("fields = %v", rule["fields"])
	}
	field, _ := fields[0].(map[string]any)
	if field["path"] != "spec.containers[*].env" || field["action"] != "remove" || field["marker"] != "<hidden>" {
		t.Errorf("field = %v", field)
	}
	replacements, _ := rule["replace"].([]any)
	if len(replacements) != 2 {
		t.Fatalf("replace = %v", rule["replace"])
	}
	literal, _ := replacements[0].(map[string]any)
	if _, present := literal["text"]; present {
		t.Error("the literal text key must never be exposed")
	}
	pattern, _ := replacements[1].(map[string]any)
	if pattern["pattern"] != `tok-[0-9]+` || pattern["marker"] != "[TOKEN]" {
		t.Errorf("pattern = %v", pattern)
	}
}

func TestListConfiguredRulesOmitsEmptyRedactions(t *testing.T) {
	cfg := baseConfig(nil)
	cfg.Providers[0].PolicyRead = true
	env := newTestEnv(t, cfg, baseCluster())

	out := env.callOK("list_configured_rules", nil)
	providers, _ := out["providers"].([]any)
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(providers))
	}
	provider, _ := providers[0].(map[string]any)
	if _, present := provider["redactions"]; present {
		t.Error("redactions must be omitted for a provider without redaction rules")
	}
}

func TestRedactionBuildFailureFailsClosed(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"pods"},
		Fields:    []config.FieldRedaction{{Path: "spec[", Action: "remove"}},
	}}
	cluster := baseCluster()
	cluster.getObj = pod("web-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("get", getArgs("pods", "ns", "web-1"))
	if !strings.Contains(message, "authorization failed") {
		t.Fatalf("error = %q, want authorization failed", message)
	}
	if strings.Contains(message, "spec[") {
		t.Errorf("error = %q, must not leak configuration details", message)
	}
}

func TestPartialDiscoveryDoesNotCacheRedactions(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Providers[0].Redactions = []config.RedactionConfig{
		{Resources: []string{"pods"}, Replace: []config.ReplaceRedaction{{Text: "web"}}},
		{Resources: []string{"apps/deployments"}, Replace: []config.ReplaceRedaction{{Text: "db"}}},
	}
	cluster := baseCluster()
	cluster.canonicalErr = map[string]error{
		"apps/deployments": fmt.Errorf("%w: %w: %q",
			kube.ErrUnknownResource, kube.ErrPartialDiscovery, "apps/deployments"),
	}
	cluster.getObj = pod("web-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if out := env.callOK("get", getArgs("pods", "ns", "web-1")); out["name"] != "web-1" {
		t.Fatalf("healthy get failed: %v", out)
	}
	env.srv.policyMu.Lock()
	cached := len(env.srv.redactions)
	env.srv.policyMu.Unlock()
	if cached != 0 {
		t.Fatalf("partial-discovery redaction engine was cached (%d entries)", cached)
	}

	// Once discovery is complete the engine is cached again.
	delete(cluster.canonicalErr, "apps/deployments")
	if out := env.callOK("get", getArgs("pods", "ns", "web-1")); out["name"] != "web-1" {
		t.Fatalf("second get failed: %v", out)
	}
	env.srv.policyMu.Lock()
	cached = len(env.srv.redactions)
	env.srv.policyMu.Unlock()
	if cached != 1 {
		t.Fatalf("complete-discovery redaction engines = %d, want 1", cached)
	}
}
