package server

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
)

// logPod builds a pod fixture with the given container names.
func logPod(name, namespace string, containers ...string) *unstructured.Unstructured {
	obj := pod(name, namespace, nil)
	items := make([]any, len(containers))
	for i, container := range containers {
		items[i] = map[string]any{"name": container}
	}
	obj.Object["spec"] = map[string]any{"containers": items}
	return obj
}

// logsArgs builds the arguments of a logs call for the "test"/"ctx" provider.
func logsArgs(namespace, podName string, extra map[string]any) map[string]any {
	args := map[string]any{
		"provider": "test", "context": "ctx",
		"namespace": namespace, "pod": podName,
	}
	for key, value := range extra {
		args[key] = value
	}
	return args
}

// logsAllowConfig allows pods/log:get in the given namespaces.
func logsAllowConfig(namespaces []string) *config.Config {
	return baseConfig([]config.RuleConfig{allowRule(namespaces, grant("pods/log", policy.VerbGet))})
}

func TestLogsDefaultsSingleContainer(t *testing.T) {
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsData = []byte("hello\nworld\n")
	env := newTestEnv(t, logsAllowConfig([]string{"ns"}), cluster)

	out := env.callOK("logs", logsArgs("ns", "web-1", nil))
	if out["provider"] != "test" || out["context"] != "ctx" {
		t.Errorf("provider/context = %v/%v", out["provider"], out["context"])
	}
	if out["resource"] != "pods/log" {
		t.Errorf("resource = %v, want canonical pods/log", out["resource"])
	}
	if out["namespace"] != "ns" || out["pod"] != "web-1" {
		t.Errorf("namespace/pod = %v/%v", out["namespace"], out["pod"])
	}
	if out["container"] != "main" {
		t.Errorf("container = %v, want the pod's only container", out["container"])
	}
	if out["content"] != "hello\nworld\n" {
		t.Errorf("content = %q", out["content"])
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v, want false", out["truncated"])
	}
	if cluster.logsCalls != 1 {
		t.Fatalf("logsCalls = %d, want 1", cluster.logsCalls)
	}
	if cluster.lastLogsNamespace != "ns" || cluster.lastLogsPod != "web-1" {
		t.Errorf("logs call = %q/%q", cluster.lastLogsNamespace, cluster.lastLogsPod)
	}
	opts := cluster.lastLogOptions
	if opts.Container != "main" {
		t.Errorf("container option = %q", opts.Container)
	}
	if opts.TailLines == nil || *opts.TailLines != 500 {
		t.Errorf("tailLines = %v, want the default 500", opts.TailLines)
	}
	if opts.LimitBytes == nil || *opts.LimitBytes != 262144+1 {
		t.Errorf("limitBytes = %v, want max_log_bytes+1", opts.LimitBytes)
	}
	if opts.SinceSeconds != nil {
		t.Errorf("sinceSeconds = %v, want nil", *opts.SinceSeconds)
	}
	if opts.Previous || opts.Timestamps {
		t.Errorf("previous/timestamps = %v/%v, want false", opts.Previous, opts.Timestamps)
	}
}

func TestLogsForwardsExplicitOptions(t *testing.T) {
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main", "sidecar")
	cluster.logsData = []byte("line\n")
	env := newTestEnv(t, logsAllowConfig([]string{"ns"}), cluster)

	out := env.callOK("logs", logsArgs("ns", "web-1", map[string]any{
		"container": "sidecar", "previous": true, "timestamps": true,
		"tailLines": 42, "sinceSeconds": 90,
	}))
	if out["container"] != "sidecar" {
		t.Errorf("container = %v", out["container"])
	}
	opts := cluster.lastLogOptions
	if opts.Container != "sidecar" {
		t.Errorf("container option = %q", opts.Container)
	}
	if !opts.Previous || !opts.Timestamps {
		t.Errorf("previous/timestamps = %v/%v, want true", opts.Previous, opts.Timestamps)
	}
	if opts.TailLines == nil || *opts.TailLines != 42 {
		t.Errorf("tailLines = %v, want 42", opts.TailLines)
	}
	if opts.SinceSeconds == nil || *opts.SinceSeconds != 90 {
		t.Errorf("sinceSeconds = %v, want 90", opts.SinceSeconds)
	}
}

func TestLogsTailLinesClamped(t *testing.T) {
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsData = []byte("line\n")
	env := newTestEnv(t, logsAllowConfig([]string{"ns"}), cluster)

	env.callOK("logs", logsArgs("ns", "web-1", map[string]any{"tailLines": 100000}))
	if cluster.lastLogOptions.TailLines == nil || *cluster.lastLogOptions.TailLines != 500 {
		t.Fatalf("tailLines = %v, want the 500 cap", cluster.lastLogOptions.TailLines)
	}
}

func TestLogsMultiContainerRequiresContainer(t *testing.T) {
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main", "sidecar")
	env := newTestEnv(t, logsAllowConfig([]string{"ns"}), cluster)

	message := env.callErr("logs", logsArgs("ns", "web-1", nil))
	if !strings.Contains(message, "container is required: the pod has 2 containers") {
		t.Fatalf("error = %q, want the container-required validation error", message)
	}
	if cluster.logsCalls != 0 {
		t.Fatalf("logsCalls = %d, want 0", cluster.logsCalls)
	}

	out := env.callOK("logs", logsArgs("ns", "web-1", map[string]any{"container": "sidecar"}))
	if out["container"] != "sidecar" {
		t.Fatalf("container = %v, want sidecar", out["container"])
	}
	if cluster.logsCalls != 1 {
		t.Fatalf("logsCalls = %d, want 1", cluster.logsCalls)
	}
}

func TestLogsNegativeBoundsRejected(t *testing.T) {
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	env := newTestEnv(t, logsAllowConfig([]string{"ns"}), cluster)

	if message := env.callErr("logs", logsArgs("ns", "web-1", map[string]any{"tailLines": -1})); !strings.Contains(message, "tailLines") {
		t.Errorf("tailLines error = %q", message)
	}
	if message := env.callErr("logs", logsArgs("ns", "web-1", map[string]any{"sinceSeconds": -1})); !strings.Contains(message, "sinceSeconds") {
		t.Errorf("sinceSeconds error = %q", message)
	}
	if message := env.callErr("logs", logsArgs("ns", "web-1", map[string]any{"container": "Not_A_Label"})); !strings.Contains(message, "invalid container") {
		t.Errorf("container error = %q", message)
	}
	if cluster.logsCalls != 0 {
		t.Fatalf("logsCalls = %d, want 0", cluster.logsCalls)
	}
}

func TestLogsDenialsAreNotFound(t *testing.T) {
	// A scope-only deny rule short-circuits before the fetch.
	denyCfg := baseConfig([]config.RuleConfig{
		{Namespaces: []string{"ns"}, Effect: policy.EffectDeny},
		allowRule([]string{"ns"}, grant("pods/log", policy.VerbGet)),
	})
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	env := newTestEnv(t, denyCfg, cluster)
	if message := env.callErr("logs", logsArgs("ns", "web-1", nil)); !strings.Contains(message, "not found") {
		t.Fatalf("deny error = %q, want not found", message)
	}
	if cluster.logsCalls != 0 || cluster.getCalls != 0 {
		t.Fatalf("calls = %d/%d, want 0/0 (pre-check must short-circuit)", cluster.getCalls, cluster.logsCalls)
	}

	// A label-filter deny applies after the pod fetch but before the log read.
	labelCfg := baseConfig([]config.RuleConfig{
		{Namespaces: []string{"ns"}, Effect: policy.EffectDeny, Capabilities: []config.CapabilityGrant{{
			Resource: "pods/log",
			Verb:     policy.VerbGet,
			Filter:   policy.CapabilityFilter{Labels: policy.LabelFilter{Require: []string{"noai"}}},
		}}},
		allowRule([]string{"ns"}, grant("pods/log", policy.VerbGet)),
	})
	cluster = baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.getObj.SetLabels(map[string]string{"noai": "true"})
	env = newTestEnv(t, labelCfg, cluster)
	if message := env.callErr("logs", logsArgs("ns", "web-1", nil)); !strings.Contains(message, "not found") {
		t.Fatalf("label deny error = %q, want not found", message)
	}
	if cluster.logsCalls != 0 {
		t.Fatalf("logsCalls = %d, want 0", cluster.logsCalls)
	}

	// The namespace marker hides the pod.
	markerCfg := logsAllowConfig([]string{"ns"})
	markerCfg.Server.NamespaceMarker.Enabled = true
	cluster = baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.marked["ns"] = true
	env = newTestEnv(t, markerCfg, cluster)
	if message := env.callErr("logs", logsArgs("ns", "web-1", nil)); !strings.Contains(message, "not found") {
		t.Fatalf("marker error = %q, want not found", message)
	}
	if cluster.logsCalls != 0 {
		t.Fatalf("logsCalls = %d, want 0", cluster.logsCalls)
	}

	// A missing pod is indistinguishable from a denied one.
	cluster = baseCluster()
	env = newTestEnv(t, logsAllowConfig([]string{"ns"}), cluster)
	if message := env.callErr("logs", logsArgs("ns", "web-1", nil)); !strings.Contains(message, "not found") {
		t.Fatalf("missing pod error = %q, want not found", message)
	}
	if cluster.logsCalls != 0 {
		t.Fatalf("logsCalls = %d, want 0", cluster.logsCalls)
	}
}

func TestLogsKubeErrorsAreMapped(t *testing.T) {
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsErr = &kube.StatusError{Sentinel: kube.ErrForbidden, Code: 403}
	env := newTestEnv(t, logsAllowConfig([]string{"ns"}), cluster)

	message := env.callErr("logs", logsArgs("ns", "web-1", nil))
	if !strings.Contains(message, "forbidden") || !strings.Contains(message, "HTTP 403") {
		t.Fatalf("error = %q, want forbidden with HTTP 403", message)
	}
}

func TestLogsTruncatesAtMaxLogBytes(t *testing.T) {
	cfg := logsAllowConfig([]string{"ns"})
	cfg.Server.MaxLogBytes = 8
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsData = []byte("héllo wörld, this is long")
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("logs", logsArgs("ns", "web-1", nil))
	if out["truncated"] != true {
		t.Fatalf("truncated = %v, want true", out["truncated"])
	}
	content, _ := out["content"].(string)
	if len(content) > 8 {
		t.Errorf("content = %q, want at most 8 bytes", content)
	}
	if !utf8.ValidString(content) {
		t.Errorf("content %q is not valid UTF-8", content)
	}
}

func TestLogsResponseBudgetTruncates(t *testing.T) {
	cfg := logsAllowConfig([]string{"ns"})
	cfg.Server.MaxResponseBytes = 200
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsData = []byte(strings.Repeat("x", 1000))
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("logs", logsArgs("ns", "web-1", nil))
	if out["truncated"] != true {
		t.Fatalf("truncated = %v, want true", out["truncated"])
	}
	content, _ := out["content"].(string)
	if len(content) >= 1000 {
		t.Errorf("content length = %d, want it cut to the response budget", len(content))
	}
}

func TestLogsRedactionReplace(t *testing.T) {
	cfg := logsAllowConfig([]string{"ns"})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"pods/log"},
		Replace:   []config.ReplaceRedaction{{Text: "s3cr3t"}},
	}}
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsData = []byte("token=s3cr3t done\n")
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("logs", logsArgs("ns", "web-1", nil))
	content, _ := out["content"].(string)
	if strings.Contains(content, "s3cr3t") {
		t.Fatalf("content = %q, the literal was not redacted", content)
	}
	if !strings.Contains(content, "[REDACTED]") {
		t.Errorf("content = %q, want the default marker", content)
	}
}

func TestLogsRedactionCapBreachIsNotFound(t *testing.T) {
	cfg := logsAllowConfig([]string{"ns"})
	cfg.Server.MaxLogBytes = 9 << 20
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"pods/log"},
		Replace:   []config.ReplaceRedaction{{Pattern: "x"}},
	}}
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsData = []byte(strings.Repeat("x", 9<<20))
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("logs", logsArgs("ns", "web-1", nil)); !strings.Contains(message, "not found") {
		t.Fatalf("cap breach error = %q, want not found", message)
	}
	if cluster.logsCalls != 1 {
		t.Fatalf("logsCalls = %d, want 1 (the breach happens after the read)", cluster.logsCalls)
	}
}

func TestLogsSchemaRequiresMandatoryFields(t *testing.T) {
	env := newTestEnv(t, baseConfig(nil), baseCluster())
	required := toolRequiredFields(t, env, "logs")
	for _, field := range []string{"provider", "context", "namespace", "pod"} {
		if !required[field] {
			t.Errorf("%s is not required in the logs input schema", field)
		}
	}
	if required["container"] || required["previous"] || required["tailLines"] {
		t.Errorf("optional logs fields are marked required: %v", required)
	}
}

func TestLogsRedactionBuildFailureFailsClosed(t *testing.T) {
	cfg := logsAllowConfig([]string{"ns"})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"pods/log"},
		Fields:    []config.FieldRedaction{{Path: "spec[", Action: "remove"}},
	}}
	cluster := baseCluster()
	cluster.getObj = logPod("web-1", "ns", "main")
	cluster.logsData = []byte("token\n")
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("logs", logsArgs("ns", "web-1", nil))
	if !strings.Contains(message, "authorization failed") {
		t.Fatalf("error = %q, want authorization failed", message)
	}
	if cluster.logsCalls != 0 {
		t.Fatalf("logsCalls = %d, want 0 (a redaction build failure must precede the read)", cluster.logsCalls)
	}
}

// toolRequiredFields returns the required field names of a tool's input schema.
func toolRequiredFields(t *testing.T, env *testEnv, name string) map[string]bool {
	t.Helper()
	tools, err := env.session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	required := map[string]bool{}
	for _, tool := range tools.Tools {
		if tool.Name != name {
			continue
		}
		parsed := schemaMap(t, tool.InputSchema)
		entries, _ := parsed["required"].([]any)
		for _, entry := range entries {
			if field, ok := entry.(string); ok {
				required[field] = true
			}
		}
		return required
	}
	t.Fatalf("%s tool not found", name)
	return nil
}

// schemaMap decodes a tool input schema into a generic map.
func schemaMap(t *testing.T, schema any) map[string]any {
	t.Helper()
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	return parsed
}
