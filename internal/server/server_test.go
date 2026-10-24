package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
)

// --- fakes ---------------------------------------------------------------

type fakeCluster struct {
	resources    map[string]policy.Resource
	ambiguous    map[string]bool
	namespaced   map[string]bool
	supportsVerb map[string]bool

	canonicalErr    map[string]error
	canonicalAll    map[string][]policy.Resource
	canonicalAllErr map[string]error

	getObj    *unstructured.Unstructured
	getErr    error
	listItems []unstructured.Unstructured
	listErr   error

	marked    map[string]bool
	markerErr error

	canonicalCalls    int
	canonicalAllCalls int
	getCalls          int
	listCalls         int
	markerCalls       int
	lastListLimit     int
	lastListNamespace string
}

func (f *fakeCluster) Canonicalize(_ context.Context, raw string) (policy.Resource, bool, error) {
	f.canonicalCalls++
	if raw == "*" {
		return policy.Resource{}, true, nil
	}
	if err, ok := f.canonicalErr[raw]; ok {
		return policy.Resource{}, false, err
	}
	if f.ambiguous[raw] {
		return policy.Resource{}, false, fmt.Errorf("%w: %q", kube.ErrAmbiguousResource, raw)
	}
	res, ok := f.resources[raw]
	if !ok {
		return policy.Resource{}, false, fmt.Errorf("%w: %q", kube.ErrUnknownResource, raw)
	}
	return res, false, nil
}

func (f *fakeCluster) CanonicalizeAll(ctx context.Context, raw string) ([]policy.Resource, error) {
	f.canonicalAllCalls++
	if err, ok := f.canonicalAllErr[raw]; ok {
		return nil, err
	}
	if list, ok := f.canonicalAll[raw]; ok {
		return list, nil
	}
	res, _, err := f.Canonicalize(ctx, raw)
	if err != nil {
		return nil, err
	}
	return []policy.Resource{res}, nil
}

func (f *fakeCluster) SupportsVerb(_ context.Context, res policy.Resource, verb policy.Verb) (bool, error) {
	if f.supportsVerb == nil {
		return true, nil
	}
	if supported, ok := f.supportsVerb[res.String()+"|"+string(verb)]; ok {
		return supported, nil
	}
	return true, nil
}

func (f *fakeCluster) Namespaced(_ context.Context, res policy.Resource) (bool, error) {
	return f.namespaced[res.String()], nil
}

func (f *fakeCluster) Get(_ context.Context, _ policy.Resource, _, _ string) (*unstructured.Unstructured, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getObj == nil {
		return nil, kube.ErrNotFound
	}
	return f.getObj, nil
}

func (f *fakeCluster) List(_ context.Context, _ policy.Resource, namespace, _ string, limit int) ([]unstructured.Unstructured, error) {
	f.listCalls++
	f.lastListLimit = limit
	f.lastListNamespace = namespace
	if f.listErr != nil {
		return nil, f.listErr
	}
	items := f.listItems
	if limit >= 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (f *fakeCluster) NamespaceMarked(_ context.Context, namespace, _ string) (bool, error) {
	f.markerCalls++
	if f.markerErr != nil {
		return false, f.markerErr
	}
	return f.marked[namespace], nil
}

type fakeRegistry struct {
	cluster     Cluster
	err         error
	contexts    map[string][]string
	contextsErr map[string]error
}

func (r fakeRegistry) Cluster(_, _ string) (Cluster, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.cluster, nil
}

func (r fakeRegistry) Contexts(provider string) ([]string, error) {
	if err, ok := r.contextsErr[provider]; ok {
		return nil, err
	}
	return r.contexts[provider], nil
}

// --- harness -------------------------------------------------------------

type testEnv struct {
	t       *testing.T
	session *mcp.ClientSession
	logs    *bytes.Buffer
	srv     *Server
}

func newTestEnv(t *testing.T, cfg *config.Config, cluster *fakeCluster) *testEnv {
	t.Helper()
	return newTestEnvRegistry(t, cfg, fakeRegistry{cluster: cluster})
}

func newTestEnvRegistry(t *testing.T, cfg *config.Config, registry ClusterRegistry) *testEnv {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := New(cfg, registry, logger)

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := srv.MCPServer("test").Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return &testEnv{t: t, session: session, logs: &logs, srv: srv}
}

func (e *testEnv) call(name string, args map[string]any) *mcp.CallToolResult {
	e.t.Helper()
	res, err := e.session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		e.t.Fatalf("CallTool(%s): %v", name, err)
	}
	return res
}

func (e *testEnv) callOK(name string, args map[string]any) map[string]any {
	e.t.Helper()
	res := e.call(name, args)
	if res.IsError {
		e.t.Fatalf("%s returned an error: %s", name, resultText(e.t, res))
	}
	return decodeJSON(e.t, resultText(e.t, res))
}

func (e *testEnv) callErr(name string, args map[string]any) string {
	e.t.Helper()
	res := e.call(name, args)
	if !res.IsError {
		e.t.Fatalf("%s = %s, want an error", name, resultText(e.t, res))
	}
	return resultText(e.t, res)
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		return ""
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *mcp.TextContent", res.Content[0])
	}
	return text.Text
}

func decodeJSON(t *testing.T, text string) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("decode %q: %v", text, err)
	}
	return decoded
}

// --- fixtures ------------------------------------------------------------

func baseConfig(rules []config.RuleConfig) *config.Config {
	return &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Name:             "mcp-keel-test",
			MaxListItems:     500,
			MaxObjectBytes:   1 << 20,
			MaxResponseBytes: 8 << 20,
			NamespaceMarker:  config.NamespaceMarkerConfig{Label: "mcp-keel.io/noai"},
		},
		Providers: []config.ProviderConfig{{
			Name:     "test",
			Contexts: []string{"*"},
			Rules:    rules,
		}},
	}
}

func allowRule(namespaces []string, grants ...config.CapabilityGrant) config.RuleConfig {
	return config.RuleConfig{Namespaces: namespaces, Effect: policy.EffectAllow, Capabilities: grants}
}

func grant(resource string, verb policy.Verb) config.CapabilityGrant {
	return config.CapabilityGrant{Resource: resource, Verb: verb}
}

func baseCluster() *fakeCluster {
	return &fakeCluster{
		resources: map[string]policy.Resource{
			"pods":             {Name: "pods"},
			"core/pods":        {Name: "pods"},
			"apps/deployments": {Group: "apps", Name: "deployments"},
			"nodes":            {Name: "nodes"},
			"namespaces":       {Name: "namespaces"},
			"secrets":          {Name: "secrets"},
		},
		namespaced: map[string]bool{
			"pods":             true,
			"apps/deployments": true,
			"secrets":          true,
			"nodes":            false,
			"namespaces":       false,
		},
		marked:    map[string]bool{},
		ambiguous: map[string]bool{},
	}
}

func labelsAny(labels map[string]string) map[string]any {
	if labels == nil {
		return nil
	}
	out := make(map[string]any, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func pod(name, namespace string, labels map[string]string) *unstructured.Unstructured {
	metadata := map[string]any{
		"name":          name,
		"namespace":     namespace,
		"managedFields": []any{map[string]any{"manager": "kubectl"}},
	}
	if labels != nil {
		metadata["labels"] = labelsAny(labels)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   metadata,
		"spec":       map[string]any{"containers": []any{}},
		"status":     map[string]any{"phase": "Running"},
	}}
}

func getArgs(resource, namespace, name string) map[string]any {
	args := map[string]any{"provider": "test", "context": "ctx", "resource": resource, "name": name}
	if namespace != "" {
		args["namespace"] = namespace
	}
	return args
}

// --- tests ---------------------------------------------------------------

func TestGetPreCheckDeniesWithoutClusterCall(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("get", getArgs("apps/deployments", "ns", "web"))
	if !strings.Contains(message, "not found") {
		t.Fatalf("error = %q, want not found", message)
	}
	if cluster.getCalls != 0 {
		t.Fatalf("getCalls = %d, want 0 (pre-check must avoid the cluster call)", cluster.getCalls)
	}
}

func TestGetOutputEnvelopeAndManagedFieldsStripped(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cluster := baseCluster()
	cluster.getObj = pod("frontend-1", "ns", map[string]string{"app": "web"})
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("get", getArgs("pods", "ns", "frontend-1"))
	if out["provider"] != "test" || out["context"] != "ctx" {
		t.Errorf("provider/context = %v/%v", out["provider"], out["context"])
	}
	if out["resource"] != "pods" {
		t.Errorf("resource = %v, want canonical pods", out["resource"])
	}
	if out["namespace"] != "ns" || out["name"] != "frontend-1" {
		t.Errorf("namespace/name = %v/%v", out["namespace"], out["name"])
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v, want false", out["truncated"])
	}
	object, ok := out["object"].(map[string]any)
	if !ok {
		t.Fatalf("object = %T, want map", out["object"])
	}
	metadata, _ := object["metadata"].(map[string]any)
	if _, present := metadata["managedFields"]; present {
		t.Error("metadata.managedFields was not stripped")
	}
	if _, present := object["spec"]; !present {
		t.Error("spec was dropped unexpectedly")
	}
}

func TestGetObjectReduction(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Server.MaxObjectBytes = 120
	cluster := baseCluster()
	large := pod("frontend-1", "ns", nil)
	large.Object["data"] = strings.Repeat("x", 4096)
	cluster.getObj = large
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("get", getArgs("pods", "ns", "frontend-1"))
	if out["truncated"] != true {
		t.Fatalf("truncated = %v, want true", out["truncated"])
	}
	object, _ := out["object"].(map[string]any)
	if _, present := object["data"]; present {
		t.Error("oversized field survived reduction")
	}
	if _, present := object["spec"]; present {
		t.Error("spec survived reduction to the skeleton")
	}
	if object["kind"] != "Pod" {
		t.Errorf("kind = %v, want Pod", object["kind"])
	}
}

func TestGetResponseBudgetReducesToMinimal(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Server.MaxObjectBytes = 1 << 20
	cfg.Server.MaxResponseBytes = 1 // impossibly small: force the minimal object
	cluster := baseCluster()
	cluster.getObj = pod("frontend-1", "ns", map[string]string{"app": "web"})
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("get", getArgs("pods", "ns", "frontend-1"))
	if out["truncated"] != true {
		t.Fatalf("truncated = %v, want true", out["truncated"])
	}
	object, _ := out["object"].(map[string]any)
	metadata, _ := object["metadata"].(map[string]any)
	if metadata["name"] != "frontend-1" {
		t.Errorf("minimal metadata.name = %v, want frontend-1", metadata["name"])
	}
	if _, present := metadata["labels"]; present {
		t.Error("minimal metadata kept labels")
	}
}

func TestGetDenialIsNotFound(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"},
		config.CapabilityGrant{
			Resource: "pods",
			Verb:     policy.VerbGet,
			Filter:   policy.CapabilityFilter{Names: policy.NameFilter{Include: []string{"frontend-*"}}},
		},
	)})
	cluster := baseCluster()
	cluster.getObj = pod("backend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("get", getArgs("pods", "ns", "backend-1"))
	if !strings.Contains(message, "not found") {
		t.Fatalf("error = %q, want not found", message)
	}
	if cluster.getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1", cluster.getCalls)
	}
}

func TestGetForbiddenCarriesHTTPStatus(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cluster := baseCluster()
	cluster.getErr = &kube.StatusError{Sentinel: kube.ErrForbidden, Code: 403}
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("get", getArgs("pods", "ns", "frontend-1"))
	if !strings.Contains(message, "forbidden") || !strings.Contains(message, "HTTP 403") {
		t.Fatalf("error = %q, want forbidden with HTTP 403", message)
	}
}

func TestUnknownAndAmbiguousResource(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cluster := baseCluster()
	cluster.ambiguous["events"] = true
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("widgets", "ns", "widget")); !strings.Contains(message, "unknown resource") {
		t.Errorf("unknown resource error = %q", message)
	}
	if message := env.callErr("get", getArgs("events", "ns", "e")); !strings.Contains(message, "ambiguous resource") {
		t.Errorf("ambiguous resource error = %q", message)
	}
	if message := env.callErr("get", getArgs("*", "ns", "x")); !strings.Contains(message, "unknown resource") {
		t.Errorf("wildcard resource error = %q", message)
	}
}

func TestScopeValidation(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{""}, grant("nodes", policy.VerbGet))})
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("nodes", "ns", "node-1")); !strings.Contains(message, "not allowed for a cluster-scoped") {
		t.Errorf("cluster-scoped namespace error = %q", message)
	}

	cfgNS := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	envNS := newTestEnv(t, cfgNS, cluster)
	if message := envNS.callErr("get", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "name": "frontend-1",
	}); !strings.Contains(message, "namespace is required") {
		t.Errorf("namespaced missing namespace error = %q", message)
	}
}

func TestListDenialReturnsEmptyResult(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	})
	items, ok := out["items"].([]any)
	if !ok || len(items) != 0 {
		t.Fatalf("items = %v, want an empty list", out["items"])
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v, want false", out["truncated"])
	}
	if cluster.listCalls != 0 {
		t.Fatalf("listCalls = %d, want 0 (pre-check must avoid the cluster call)", cluster.listCalls)
	}
}

func TestListPerItemFilteringHidesDeniedItems(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"},
		config.CapabilityGrant{
			Resource: "pods",
			Verb:     policy.VerbList,
			Filter:   policy.CapabilityFilter{Labels: policy.LabelFilter{Require: []string{"app=web"}}},
		},
	)})
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
	if len(items) != 1 {
		t.Fatalf("items = %v, want exactly the allowed item", items)
	}
	metadata, _ := items[0].(map[string]any)["metadata"].(map[string]any)
	if metadata["name"] != "web-1" {
		t.Errorf("returned item = %v, want web-1", metadata["name"])
	}
	if _, present := out["hidden"]; present {
		t.Error("hidden count must never be returned")
	}
}

func TestListAllNamespacesEchoesEmptyNamespace(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbList))})
	cluster := baseCluster()
	cluster.listItems = []unstructured.Unstructured{*pod("web-1", "ns", nil)}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods",
	})
	if out["namespace"] != "" {
		t.Errorf("namespace = %v, want empty for all-namespaces", out["namespace"])
	}
	if cluster.lastListNamespace != "" {
		t.Errorf("list namespace = %q, want empty", cluster.lastListNamespace)
	}
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
}

func TestListWindowTruncation(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbList))})
	cluster := baseCluster()
	cluster.listItems = []unstructured.Unstructured{
		*pod("p1", "ns", nil), *pod("p2", "ns", nil), *pod("p3", "ns", nil),
	}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns", "limit": 2,
	})
	if cluster.lastListLimit != 3 {
		t.Errorf("server-side limit = %d, want limit+1 = 3", cluster.lastListLimit)
	}
	items, _ := out["items"].([]any)
	if len(items) != 2 {
		t.Errorf("items = %d, want 2", len(items))
	}
	if out["truncated"] != true {
		t.Errorf("truncated = %v, want true", out["truncated"])
	}
}

func TestListResponseBudget(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbList))})
	cfg.Server.MaxResponseBytes = 1000
	cluster := baseCluster()
	small := pod("small", "ns", nil)
	huge := pod("huge", "ns", nil)
	huge.Object["data"] = strings.Repeat("y", 5000)
	cluster.listItems = []unstructured.Unstructured{*small, *huge}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	})
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1 (budget stops before the huge item)", len(items))
	}
	if out["truncated"] != true {
		t.Errorf("truncated = %v, want true", out["truncated"])
	}
}

func TestNamespaceMarkerDeniesUnlessExempt(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Server.NamespaceMarker.Enabled = true
	cluster := baseCluster()
	cluster.marked["ns"] = true
	cluster.getObj = pod("frontend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("pods", "ns", "frontend-1")); !strings.Contains(message, "not found") {
		t.Fatalf("marker denial = %q, want not found", message)
	}

	exemptCfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"},
		config.CapabilityGrant{
			Resource: "pods",
			Verb:     policy.VerbGet,
			Filter:   policy.CapabilityFilter{NamespaceMarkerExempt: true},
		},
	)})
	exemptCfg.Server.NamespaceMarker.Enabled = true
	envExempt := newTestEnv(t, exemptCfg, cluster)
	if out := envExempt.callOK("get", getArgs("pods", "ns", "frontend-1")); out["name"] != "frontend-1" {
		t.Fatalf("exempt get failed: %v", out)
	}
}

func TestNamespaceMarkerCheckFailureFailsClosed(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Server.NamespaceMarker.Enabled = true
	cluster := baseCluster()
	cluster.markerErr = errors.New("namespaces get forbidden")
	cluster.getObj = pod("frontend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("pods", "ns", "frontend-1")); !strings.Contains(message, "not found") {
		t.Fatalf("marker check failure = %q, want not found", message)
	}
}

func TestListConfiguredRulesGatedByPolicyRead(t *testing.T) {
	cfg := &config.Config{
		Version: 1,
		Server:  config.ServerConfig{Name: "test", MaxListItems: 500, MaxObjectBytes: 1 << 20, MaxResponseBytes: 1 << 20},
		Providers: []config.ProviderConfig{
			{
				Name:       "b-hidden",
				Contexts:   []string{"*"},
				PolicyRead: false,
				Rules:      []config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))},
			},
			{
				Name:       "c-visible",
				Contexts:   []string{"*"},
				PolicyRead: true,
				Rules: []config.RuleConfig{
					{Namespaces: []string{"secret-ns"}, Effect: policy.EffectDeny},
					allowRule([]string{"ns"}, config.CapabilityGrant{
						Resource: "pods",
						Verb:     policy.VerbList,
						Filter: policy.CapabilityFilter{
							Labels: policy.LabelFilter{Require: []string{"app=web"}},
						},
					}),
				},
			},
			{
				Name:       "a-visible",
				Contexts:   []string{"dev-*"},
				PolicyRead: true,
				Rules:      nil,
			},
		},
	}
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list_configured_rules", nil)
	providers, _ := out["providers"].([]any)
	if len(providers) != 2 {
		t.Fatalf("providers = %d, want 2 visible", len(providers))
	}
	first, _ := providers[0].(map[string]any)
	second, _ := providers[1].(map[string]any)
	if first["provider"] != "a-visible" || second["provider"] != "c-visible" {
		t.Fatalf("providers not sorted/filtered: %v, %v", first["provider"], second["provider"])
	}
	rules, _ := second["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2 (order preserved)", len(rules))
	}
	denyRule, _ := rules[0].(map[string]any)
	if denyRule["effect"] != "deny" {
		t.Errorf("rule 0 effect = %v, want deny", denyRule["effect"])
	}
	allowCaps, _ := rules[1].(map[string]any)["capabilities"].([]any)
	if len(allowCaps) != 1 {
		t.Fatalf("capabilities = %v", allowCaps)
	}
	capability, _ := allowCaps[0].(map[string]any)
	if capability["resource"] != "pods" || capability["verb"] != "list" {
		t.Errorf("capability = %v, want pods:list", capability)
	}
	labels, _ := capability["labels"].(map[string]any)
	if labels == nil {
		t.Fatal("labels filter missing")
	}
	require, _ := labels["require"].([]any)
	if len(require) != 1 || require[0] != "app=web" {
		t.Errorf("labels.require = %v", require)
	}
	if strings.Contains(resultText(t, env.call("list_configured_rules", nil)), "kubeconfig") {
		t.Error("list_configured_rules leaked kubeconfig plumbing")
	}
}

func TestListClustersGatedByPolicyRead(t *testing.T) {
	cfg := &config.Config{
		Version: 1,
		Server:  config.ServerConfig{Name: "test", MaxListItems: 500, MaxObjectBytes: 1 << 20, MaxResponseBytes: 1 << 20},
		Providers: []config.ProviderConfig{
			{Name: "hidden", Contexts: []string{"*"}, PolicyRead: false},
			{Name: "b-visible", Contexts: []string{"b-*"}, PolicyRead: true},
			{Name: "a-visible", Contexts: []string{"a-*", "c-*"}, PolicyRead: true},
		},
	}
	registry := fakeRegistry{
		contexts: map[string][]string{
			"a-visible": {"a-1", "c-2"},
			"b-visible": {},
		},
		contextsErr: map[string]error{
			"b-visible": errors.New("kubeconfig unreadable"),
		},
	}
	env := newTestEnvRegistry(t, cfg, registry)

	out := env.callOK("list_clusters", nil)
	providers, _ := out["providers"].([]any)
	if len(providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(providers))
	}
	first, _ := providers[0].(map[string]any)
	if first["provider"] != "a-visible" {
		t.Errorf("first provider = %v, want a-visible", first["provider"])
	}
	patterns, _ := first["context_patterns"].([]any)
	if len(patterns) != 2 || patterns[0] != "a-*" || patterns[1] != "c-*" {
		t.Errorf("context_patterns = %v, want [a-* c-*]", patterns)
	}
	contexts, _ := first["contexts"].([]any)
	if len(contexts) != 2 || contexts[0] != "a-1" || contexts[1] != "c-2" {
		t.Errorf("contexts = %v, want [a-1 c-2]", contexts)
	}

	// An unreadable kubeconfig keeps the provider but yields no contexts.
	second, _ := providers[1].(map[string]any)
	if second["provider"] != "b-visible" {
		t.Errorf("second provider = %v, want b-visible", second["provider"])
	}
	secondContexts, ok := second["contexts"].([]any)
	if !ok || len(secondContexts) != 0 {
		t.Errorf("contexts = %v, want [] for an unreadable kubeconfig", second["contexts"])
	}
	secondPatterns, _ := second["context_patterns"].([]any)
	if len(secondPatterns) != 1 || secondPatterns[0] != "b-*" {
		t.Errorf("context_patterns = %v, want [b-*]", secondPatterns)
	}
}

func TestListClusterScopedAndScopeRejection(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{""}, grant("nodes", policy.VerbList))})
	cluster := baseCluster()
	cluster.listItems = []unstructured.Unstructured{{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "Node",
			"metadata":   map[string]any{"name": "node-1", "managedFields": []any{}},
		},
	}}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "nodes",
	})
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	if out["namespace"] != "" {
		t.Errorf("namespace = %v, want empty for cluster scope", out["namespace"])
	}
	if local, _ := items[0].(map[string]any)["metadata"].(map[string]any); local != nil {
		if _, present := local["managedFields"]; present {
			t.Error("managedFields was not stripped from a list item")
		}
	}

	// A namespace is rejected for a cluster-scoped resource.
	env2 := newTestEnv(t, cfg, baseCluster())
	if message := env2.callErr("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "nodes", "namespace": "ns",
	}); !strings.Contains(message, "not allowed for a cluster-scoped") {
		t.Fatalf("cluster-scoped list namespace error = %q", message)
	}
}

func TestListNamespaceMarkerHidesItems(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbList))})
	cfg.Server.NamespaceMarker.Enabled = true
	cluster := baseCluster()
	cluster.marked["ns"] = true
	cluster.listItems = []unstructured.Unstructured{*pod("web-1", "ns", nil)}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	})
	items, _ := out["items"].([]any)
	if len(items) != 0 {
		t.Fatalf("items = %v, want all hidden in a marked namespace", items)
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v, want false", out["truncated"])
	}
	if cluster.markerCalls != 1 {
		t.Errorf("markerCalls = %d, want 1 (cached per namespace)", cluster.markerCalls)
	}
}

func TestRegistryErrorsAreSafe(t *testing.T) {
	cfg := baseConfig(nil)
	env := newTestEnvRegistry(t, cfg, fakeRegistry{err: fmt.Errorf("%w: %q", kube.ErrUnknownProvider, "nope")})

	message := env.callErr("get", getArgs("pods", "ns", "frontend-1"))
	if !strings.Contains(message, "unknown provider") {
		t.Fatalf("error = %q, want unknown provider", message)
	}
}

// --- pre-check (Major 1) -------------------------------------------------

func TestPreCheckScopeOnlyDenyAvoidsClusterCall(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		{Namespaces: []string{"ns"}, Effect: policy.EffectDeny},
		allowRule([]string{"ns"}, grant("pods", policy.VerbGet)),
	})
	cluster := baseCluster()
	cluster.getObj = pod("frontend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("pods", "ns", "frontend-1")); !strings.Contains(message, "not found") {
		t.Fatalf("error = %q, want not found", message)
	}
	if cluster.getCalls != 0 {
		t.Fatalf("getCalls = %d, want 0 (scope-only deny must short-circuit)", cluster.getCalls)
	}
}

func TestPreCheckScopeOnlyDenyAvoidsClusterCallList(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		{Namespaces: []string{"ns"}, Effect: policy.EffectDeny},
		allowRule([]string{"ns"}, grant("pods", policy.VerbList)),
	})
	cluster := baseCluster()
	cluster.listItems = []unstructured.Unstructured{*pod("frontend-1", "ns", nil)}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	})
	if items, _ := out["items"].([]any); len(items) != 0 {
		t.Fatalf("items = %v, want empty", out["items"])
	}
	if cluster.listCalls != 0 {
		t.Fatalf("listCalls = %d, want 0 (scope-only deny must short-circuit)", cluster.listCalls)
	}
}

func TestPreCheckDenyNameFilterShortCircuitsOnlyOnMatch(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		{Namespaces: []string{"ns"}, Effect: policy.EffectDeny, Capabilities: []config.CapabilityGrant{{
			Resource: "pods",
			Verb:     policy.VerbGet,
			Filter:   policy.CapabilityFilter{Names: policy.NameFilter{Include: []string{"frontend-*"}}},
		}}},
		allowRule([]string{"ns"}, grant("pods", policy.VerbGet)),
	})
	cluster := baseCluster()
	cluster.getObj = pod("backend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("pods", "ns", "frontend-1")); !strings.Contains(message, "not found") {
		t.Fatalf("name-filter deny error = %q, want not found", message)
	}
	if cluster.getCalls != 0 {
		t.Fatalf("getCalls = %d, want 0 for a pre-evaluable name-filter deny", cluster.getCalls)
	}

	// A non-matching name is not pre-denied: the allow rule wins after fetch.
	if out := env.callOK("get", getArgs("pods", "ns", "backend-1")); out["name"] != "backend-1" {
		t.Fatalf("non-matching name was over-denied: %v", out)
	}
	if cluster.getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1", cluster.getCalls)
	}
}

func TestPreCheckLabelFilterDoesNotShortCircuit(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		{Namespaces: []string{"ns"}, Effect: policy.EffectDeny, Capabilities: []config.CapabilityGrant{{
			Resource: "pods",
			Verb:     policy.VerbGet,
			Filter:   policy.CapabilityFilter{Labels: policy.LabelFilter{Require: []string{"noai"}}},
		}}},
		allowRule([]string{"ns"}, grant("pods", policy.VerbGet)),
	})
	cluster := baseCluster()
	cluster.getObj = pod("frontend-1", "ns", map[string]string{"noai": "true"})
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("pods", "ns", "frontend-1")); !strings.Contains(message, "not found") {
		t.Fatalf("label-filter deny error = %q, want not found", message)
	}
	if cluster.getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1 (label filters are not pre-evaluable)", cluster.getCalls)
	}
}

func TestPreCheckEarlierAllowIsNeverShadowed(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		allowRule([]string{"ns"}, grant("pods", policy.VerbGet)),
		{Namespaces: []string{"ns"}, Effect: policy.EffectDeny, Capabilities: []config.CapabilityGrant{{
			Resource: "pods",
			Verb:     policy.VerbGet,
			Filter:   policy.CapabilityFilter{Names: policy.NameFilter{Include: []string{"frontend-*"}}},
		}}},
	})
	cluster := baseCluster()
	cluster.getObj = pod("frontend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if out := env.callOK("get", getArgs("pods", "ns", "frontend-1")); out["name"] != "frontend-1" {
		t.Fatalf("earlier allow was shadowed by a later deny: %v", out)
	}
	if cluster.getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1", cluster.getCalls)
	}
}

func TestPreCheckNoAllowRuleDeniesWithoutCall(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{{
		Namespaces:   []string{"ns"},
		Effect:       policy.EffectDeny,
		Capabilities: []config.CapabilityGrant{grant("secrets", policy.VerbGet)},
	}})
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("get", getArgs("pods", "ns", "frontend-1")); !strings.Contains(message, "not found") {
		t.Fatalf("error = %q, want not found", message)
	}
	if cluster.getCalls != 0 {
		t.Fatalf("getCalls = %d, want 0", cluster.getCalls)
	}
}

// --- policy build resilience (Major 2/3) ---------------------------------

func TestPartialDiscoveryDoesNotDisableProvider(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		allowRule([]string{"ns"}, grant("pods", policy.VerbGet)),
		allowRule([]string{"ns"}, grant("apps/deployments", policy.VerbGet)),
	})
	cluster := baseCluster()
	cluster.canonicalErr = map[string]error{
		"apps/deployments": fmt.Errorf("%w: %w: %q",
			kube.ErrUnknownResource, kube.ErrPartialDiscovery, "apps/deployments"),
	}
	cluster.getObj = pod("frontend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if out := env.callOK("get", getArgs("pods", "ns", "frontend-1")); out["name"] != "frontend-1" {
		t.Fatalf("healthy resource was denied: %v", out)
	}

	env.srv.policyMu.Lock()
	cached := len(env.srv.policyByKey)
	env.srv.policyMu.Unlock()
	if cached != 0 {
		t.Fatalf("partial-discovery policy was cached (%d entries)", cached)
	}

	if message := env.callErr("get", getArgs("apps/deployments", "ns", "web")); !strings.Contains(message, "unknown resource") {
		t.Fatalf("unresolvable resource error = %q, want unknown resource", message)
	}
	if cluster.getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1 (only the healthy resource fetched)", cluster.getCalls)
	}
}

func TestUnresolvableCapabilityDropsRuleOnly(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		allowRule([]string{"ns"}, grant("pods", policy.VerbGet)),
		allowRule([]string{"ns"}, grant("widgets", policy.VerbGet)),
	})
	cluster := baseCluster()
	cluster.resources["widgets"] = policy.Resource{Name: "widgets"}
	cluster.canonicalErr = map[string]error{
		"widgets": fmt.Errorf("%w: %q", kube.ErrUnknownResource, "widgets"),
	}
	cluster.getObj = pod("frontend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	if out := env.callOK("get", getArgs("pods", "ns", "frontend-1")); out["name"] != "frontend-1" {
		t.Fatalf("healthy resource was denied: %v", out)
	}

	env.srv.policyMu.Lock()
	cached := len(env.srv.policyByKey)
	env.srv.policyMu.Unlock()
	if cached != 1 {
		t.Fatalf("complete-discovery policy cached entries = %d, want 1", cached)
	}

	if message := env.callErr("get", getArgs("widgets", "ns", "w")); !strings.Contains(message, "unknown resource") {
		t.Fatalf("unresolvable resource error = %q, want unknown resource", message)
	}
}

func TestAmbiguousSensitiveResourceProtectsAllForms(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{
		allowRule([]string{"ns"}, config.CapabilityGrant{Resource: "*", Wildcard: true, Verb: policy.VerbGet}),
	})
	cfg.Server.AdditionalSensitiveResources = []string{"events", "widgets"}
	cluster := baseCluster()
	cluster.resources["core/events"] = policy.Resource{Name: "events"}
	cluster.resources["events.k8s.io/events"] = policy.Resource{Group: "events.k8s.io", Name: "events"}
	cluster.namespaced["events"] = true
	cluster.namespaced["events.k8s.io/events"] = true
	cluster.canonicalAll = map[string][]policy.Resource{
		"events": {{Name: "events"}, {Group: "events.k8s.io", Name: "events"}},
	}
	cluster.canonicalAllErr = map[string]error{
		"widgets": errors.New("discovery unavailable"),
	}
	cluster.getObj = pod("frontend-1", "ns", nil)
	env := newTestEnv(t, cfg, cluster)

	for _, resource := range []string{"core/events", "events.k8s.io/events"} {
		if message := env.callErr("get", getArgs(resource, "ns", "e1")); !strings.Contains(message, "not found") {
			t.Fatalf("sensitive %s error = %q, want not found", resource, message)
		}
	}
	if cluster.getCalls != 0 {
		t.Fatalf("getCalls = %d, want 0 (allow * must never reach the sensitive set)", cluster.getCalls)
	}

	if out := env.callOK("get", getArgs("pods", "ns", "frontend-1")); out["name"] != "frontend-1" {
		t.Fatalf("non-sensitive resource was denied: %v", out)
	}
}

// --- limits, errors and marker details (Minor / required cases) ----------

func TestListLimitClamping(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbList))})
	cfg.Server.MaxListItems = 3
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns", "limit": 100,
	})
	if cluster.lastListLimit != 4 {
		t.Fatalf("server-side limit = %d, want max_list_items+1 = 4", cluster.lastListLimit)
	}

	env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns", "limit": -5,
	})
	if cluster.lastListLimit != 4 {
		t.Fatalf("server-side limit = %d, want max_list_items+1 = 4 for a non-positive limit", cluster.lastListLimit)
	}
}

func TestUnauthorizedCarriesHTTPStatus(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cluster := baseCluster()
	cluster.getErr = &kube.StatusError{Sentinel: kube.ErrUnauthorized, Code: 401}
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("get", getArgs("pods", "ns", "frontend-1"))
	if !strings.Contains(message, "unauthorized") || !strings.Contains(message, "HTTP 401") {
		t.Fatalf("error = %q, want unauthorized with HTTP 401", message)
	}
}

func TestEmptyRequiredFieldsRejected(t *testing.T) {
	env := newTestEnv(t, baseConfig(nil), baseCluster())

	if message := env.callErr("get", map[string]any{
		"provider": "test", "context": "ctx", "resource": "", "name": "frontend-1",
	}); !strings.Contains(message, "resource must not be empty") {
		t.Fatalf("empty resource error = %q", message)
	}

	// A missing required field is rejected by the tool schema before the handler.
	if message := env.callErr("get", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	}); message == "" {
		t.Fatal("missing name did not produce an error")
	}
}

func TestGetSchemaRequiresMandatoryFields(t *testing.T) {
	env := newTestEnv(t, baseConfig(nil), baseCluster())
	tools, err := env.session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var schema any
	for _, tool := range tools.Tools {
		if tool.Name == "get" {
			schema = tool.InputSchema
		}
	}
	if schema == nil {
		t.Fatal("get tool not found")
	}
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	required, _ := parsed["required"].([]any)
	for _, field := range []string{"provider", "context", "resource", "name"} {
		found := false
		for _, entry := range required {
			if entry == field {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s is not required in the get input schema: %s", field, data)
		}
	}
}

func TestListNamespaceMarkerExemption(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, config.CapabilityGrant{
		Resource: "pods",
		Verb:     policy.VerbList,
		Filter:   policy.CapabilityFilter{NamespaceMarkerExempt: true},
	})})
	cfg.Server.NamespaceMarker.Enabled = true
	cluster := baseCluster()
	cluster.marked["ns"] = true
	cluster.listItems = []unstructured.Unstructured{*pod("web-1", "ns", nil)}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods", "namespace": "ns",
	})
	if items, _ := out["items"].([]any); len(items) != 1 {
		t.Fatalf("items = %v, want the exempted item", out["items"])
	}
}

func TestListNamespaceMarkerAcrossNamespaces(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"*"}, grant("pods", policy.VerbList))})
	cfg.Server.NamespaceMarker.Enabled = true
	cluster := baseCluster()
	cluster.marked["ns1"] = true
	cluster.listItems = []unstructured.Unstructured{
		*pod("a", "ns1", nil),
		*pod("b", "ns2", nil),
		*pod("c", "ns1", nil),
	}
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("list", map[string]any{
		"provider": "test", "context": "ctx", "resource": "pods",
	})
	items, _ := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %d, want only the unmarked namespace", len(items))
	}
	item, _ := items[0].(map[string]any)
	metadata, _ := item["metadata"].(map[string]any)
	if metadata["namespace"] != "ns2" {
		t.Errorf("returned namespace = %v, want ns2", metadata["namespace"])
	}
	if cluster.markerCalls != 2 {
		t.Errorf("markerCalls = %d, want 2 (one per distinct namespace)", cluster.markerCalls)
	}
}
