package server

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
)

// promConfig builds a config with a single provider granting the given rules and
// with a "main" Prometheus datasource, plus realistic Prometheus server limits.
func promConfig(rules []config.RuleConfig) *config.Config {
	cfg := baseConfig(rules)
	cfg.Providers[0].Prometheus = []config.PrometheusDatasource{{
		Name: "main", Namespace: "monitoring", Service: "prometheus-k8s", Port: 9090,
	}}
	cfg.Server.MaxPrometheusQueryLength = 8192
	cfg.Server.MaxPrometheusQueryRange = config.Duration(24 * time.Hour)
	cfg.Server.MaxPrometheusQueryPoints = 11000
	cfg.Server.MaxPrometheusResponseBytes = 1 << 20
	cfg.Server.PrometheusTimeout = config.Duration(10 * time.Second)
	cfg.Server.MaxPrometheusConcurrency = 4
	return cfg
}

func promAllowRule(namespaces []string, verb policy.Verb) config.RuleConfig {
	return allowRule(namespaces, config.CapabilityGrant{Resource: "prometheus", Verb: verb})
}

func promDenyAllRule() config.RuleConfig {
	return config.RuleConfig{
		Namespaces: []string{"monitoring"}, Effect: policy.EffectDeny,
		Capabilities: []config.CapabilityGrant{{
			Resource: "prometheus", Verb: policy.VerbWildcard, VerbWildcard: true,
		}},
	}
}

func promVectorResponse() *kube.PrometheusResponse {
	return &kube.PrometheusResponse{
		Data: map[string]any{
			"resultType": "vector",
			"result": []any{
				map[string]any{"metric": map[string]any{"__name__": "up"}, "value": []any{"1", "secret-token"}},
			},
		},
		Warnings: []string{"warn"},
	}
}

func promServiceLabels() map[string]string {
	return map[string]string{"app": "prometheus"}
}

func promQueryArgs(extra map[string]any) map[string]any {
	args := map[string]any{"provider": "test", "context": "ctx", "datasource": "main", "query": "up"}
	for key, value := range extra {
		args[key] = value
	}
	return args
}

func promRangeArgs(extra map[string]any) map[string]any {
	args := map[string]any{
		"provider": "test", "context": "ctx", "datasource": "main", "query": "up",
		"start": "2026-11-19T09:00:00Z", "end": "2026-11-19T10:00:00Z", "step": "1m",
	}
	for key, value := range extra {
		args[key] = value
	}
	return args
}

func TestPrometheusQueryEnvelope(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promResp = promVectorResponse()
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("prometheus_query", promQueryArgs(nil))
	if out["provider"] != "test" || out["context"] != "ctx" || out["datasource"] != "main" {
		t.Errorf("provider/context/datasource = %v/%v/%v", out["provider"], out["context"], out["datasource"])
	}
	if out["resultType"] != "vector" {
		t.Errorf("resultType = %v, want vector", out["resultType"])
	}
	result, ok := out["result"].([]any)
	if !ok || len(result) != 1 {
		t.Fatalf("result = %T %v, want one sample", out["result"], out["result"])
	}
	warnings, _ := out["warnings"].([]any)
	if len(warnings) != 1 || warnings[0] != "warn" {
		t.Errorf("warnings = %v, want [warn]", out["warnings"])
	}
	if cluster.promQueryCalls != 1 || cluster.lastPromQuery.Query != "up" {
		t.Errorf("prometheus query call = %d, query %q", cluster.promQueryCalls, cluster.lastPromQuery.Query)
	}
	if cluster.lastPromDs.Namespace != "monitoring" || cluster.lastPromDs.Service != "prometheus-k8s" || cluster.lastPromDs.Port != 9090 {
		t.Errorf("lastPromDs = %+v", cluster.lastPromDs)
	}
}

func TestPrometheusQueryRangeValidation(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbRange)})
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("prometheus_query_range", promRangeArgs(map[string]any{"end": "2026-11-19T08:00:00Z"})); !strings.Contains(message, "must not precede") {
		t.Errorf("end before start error = %q", message)
	}
	if message := env.callErr("prometheus_query_range", promRangeArgs(map[string]any{"step": "0s"})); !strings.Contains(message, "positive") {
		t.Errorf("zero step error = %q", message)
	}
	if message := env.callErr("prometheus_query_range", promRangeArgs(map[string]any{"step": "100ms"})); !strings.Contains(message, "point limit") {
		t.Errorf("fine step error = %q", message)
	}
	if message := env.callErr("prometheus_query_range", promRangeArgs(map[string]any{"start": "yesterday"})); !strings.Contains(message, "RFC3339") {
		t.Errorf("bad start error = %q", message)
	}
	if message := env.callErr("prometheus_query", promQueryArgs(map[string]any{"query": "up\x00bad"})); !strings.Contains(message, "control") {
		t.Errorf("control char error = %q", message)
	}
	if message := env.callErr("prometheus_query", promQueryArgs(map[string]any{"query": ""})); !strings.Contains(message, "empty") {
		t.Errorf("empty query error = %q", message)
	}
}

func TestPrometheusUnknownDatasource(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", map[string]any{
		"provider": "test", "context": "ctx", "datasource": "nope", "query": "up",
	})
	if !strings.Contains(message, "unknown datasource") {
		t.Fatalf("error = %q, want unknown datasource", message)
	}
	if cluster.promServiceCalls != 0 {
		t.Fatalf("promServiceCalls = %d, want 0", cluster.promServiceCalls)
	}
}

func TestPrometheusDenialsAreNotFound(t *testing.T) {
	// A scope-only deny short-circuits before the Service fetch.
	denyCfg := promConfig([]config.RuleConfig{
		{Namespaces: []string{"monitoring"}, Effect: policy.EffectDeny},
		promAllowRule([]string{"monitoring"}, policy.VerbQuery),
	})
	cluster := baseCluster()
	env := newTestEnv(t, denyCfg, cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "not found") {
		t.Fatalf("deny error = %q, want not found", message)
	}
	if cluster.promServiceCalls != 0 || cluster.promQueryCalls != 0 {
		t.Fatalf("calls = %d/%d, want 0/0", cluster.promServiceCalls, cluster.promQueryCalls)
	}

	// A label-filter deny applies after the Service fetch but before the query.
	labelCfg := promConfig([]config.RuleConfig{
		{Namespaces: []string{"monitoring"}, Effect: policy.EffectDeny, Capabilities: []config.CapabilityGrant{{
			Resource: "prometheus", Verb: policy.VerbQuery,
			Filter: policy.CapabilityFilter{Labels: policy.LabelFilter{Require: []string{"noai"}}},
		}}},
		promAllowRule([]string{"monitoring"}, policy.VerbQuery),
	})
	cluster = baseCluster()
	cluster.promServiceLabels = map[string]string{"noai": "true"}
	env = newTestEnv(t, labelCfg, cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "not found") {
		t.Fatalf("label deny error = %q, want not found", message)
	}
	if cluster.promQueryCalls != 0 {
		t.Fatalf("promQueryCalls = %d, want 0", cluster.promQueryCalls)
	}

	// A missing Service is indistinguishable from a denied one.
	cluster = baseCluster()
	cluster.promServiceErr = kube.ErrNotFound
	env = newTestEnv(t, promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)}), cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "not found") {
		t.Fatalf("missing service error = %q, want not found", message)
	}
}

func TestPrometheusNameAndLabelFilters(t *testing.T) {
	// names filter matches the datasource name (configuration).
	nameCfg := promConfig([]config.RuleConfig{{
		Namespaces: []string{"monitoring"}, Effect: policy.EffectAllow,
		Capabilities: []config.CapabilityGrant{{
			Resource: "prometheus", Verb: policy.VerbQuery,
			Filter: policy.CapabilityFilter{Names: policy.NameFilter{Include: []string{"main"}}},
		}},
	}})
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promResp = promVectorResponse()
	env := newTestEnv(t, nameCfg, cluster)
	if out := env.callOK("prometheus_query", promQueryArgs(nil)); out["datasource"] != "main" {
		t.Fatalf("name-filtered query failed: %v", out)
	}

	// labels filter matches the Service labels (cluster state).
	labelCfg := promConfig([]config.RuleConfig{{
		Namespaces: []string{"monitoring"}, Effect: policy.EffectAllow,
		Capabilities: []config.CapabilityGrant{{
			Resource: "prometheus", Verb: policy.VerbQuery,
			Filter: policy.CapabilityFilter{Labels: policy.LabelFilter{Require: []string{"app=prometheus"}}},
		}},
	}})
	cluster = baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promResp = promVectorResponse()
	env = newTestEnv(t, labelCfg, cluster)
	if out := env.callOK("prometheus_query", promQueryArgs(nil)); out["resultType"] != "vector" {
		t.Fatalf("label-filtered query failed: %v", out)
	}

	// A non-matching label denies.
	cluster = baseCluster()
	cluster.promServiceLabels = map[string]string{"app": "other"}
	env = newTestEnv(t, labelCfg, cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "not found") {
		t.Fatalf("label miss error = %q, want not found", message)
	}
}

func TestPrometheusNamespaceMarker(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Server.NamespaceMarker.Enabled = true
	cluster := baseCluster()
	cluster.marked["monitoring"] = true
	cluster.promServiceLabels = promServiceLabels()
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "not found") {
		t.Fatalf("marker denial = %q, want not found", message)
	}
	if cluster.promQueryCalls != 0 {
		t.Fatalf("promQueryCalls = %d, want 0", cluster.promQueryCalls)
	}
}

func TestPrometheusRedaction(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"prometheus"},
		Replace:   []config.ReplaceRedaction{{Text: "secret-token"}},
	}}
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promResp = promVectorResponse()
	env := newTestEnv(t, cfg, cluster)

	out := env.callOK("prometheus_query", promQueryArgs(nil))
	result, _ := out["result"].([]any)
	sample, _ := result[0].(map[string]any)
	value, _ := sample["value"].([]any)
	got, _ := value[1].(string)
	if strings.Contains(got, "secret-token") {
		t.Fatalf("result = %v, the secret was not redacted", value)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("result = %v, want the default marker", value)
	}
}

func TestPrometheusRedactionBuildFailureFailsClosed(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"prometheus"},
		Fields:    []config.FieldRedaction{{Path: "spec[", Action: "remove"}},
	}}
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(nil))
	if !strings.Contains(message, "authorization failed") {
		t.Fatalf("error = %q, want authorization failed", message)
	}
	if cluster.promQueryCalls != 0 {
		t.Fatalf("promQueryCalls = %d, want 0 (a redaction build failure precedes the read)", cluster.promQueryCalls)
	}
}

func TestPrometheusConcurrencyRejection(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promErr = kube.ErrPrometheusBusy
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(nil))
	if !strings.Contains(message, "concurrency") {
		t.Fatalf("error = %q, want a concurrency message", message)
	}
}

func TestPrometheusUpstreamErrorMapping(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promErr = kube.ErrPrometheusUpstream
	env := newTestEnv(t, cfg, cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "query failed (upstream)") {
		t.Fatalf("upstream error = %q", message)
	}

	cluster = baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promErr = &kube.PrometheusError{ErrorType: "bad_data", Message: "invalid expression"}
	env = newTestEnv(t, cfg, cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "query failed (invalid)") || !strings.Contains(message, "bad_data") {
		t.Fatalf("invalid error = %q", message)
	}

	cluster = baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promErr = kube.ErrPrometheusResponseTooLarge
	env = newTestEnv(t, cfg, cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "response too large") {
		t.Fatalf("too-large error = %q", message)
	}

	cluster = baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promErr = &kube.StatusError{Sentinel: kube.ErrForbidden, Code: 403}
	env = newTestEnv(t, cfg, cluster)
	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "forbidden") || !strings.Contains(message, "HTTP 403") {
		t.Fatalf("forbidden error = %q", message)
	}
}

// TestPrometheusDenyExpansionWithoutCRD verifies that a deny "prometheus:*"
// covers the synthetic query/range verbs even when "prometheus" does not resolve
// through discovery (no CRD), and that the policy is cached (discovery complete).
func TestPrometheusDenyExpansionWithoutCRD(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promDenyAllRule()})
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(nil))
	if !strings.Contains(message, "not found") {
		t.Fatalf("deny prometheus:* error = %q, want not found", message)
	}
	if cluster.promServiceCalls != 0 {
		t.Fatalf("promServiceCalls = %d, want 0 (deny short-circuits)", cluster.promServiceCalls)
	}

	env.srv.policyMu.Lock()
	cached := len(env.srv.policyByKey)
	env.srv.policyMu.Unlock()
	if cached != 1 {
		t.Fatalf("policy cached entries = %d, want 1 (no partial discovery)", cached)
	}
}

// TestPrometheusDenyExpansionPartialDiscovery verifies the synthetic half of a
// deny "prometheus:*" survives partial discovery (the CRD half cannot resolve).
func TestPrometheusDenyExpansionPartialDiscovery(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promDenyAllRule()})
	cluster := baseCluster()
	cluster.canonicalErr = map[string]error{"prometheus": wrapPartialDiscovery("prometheus")}
	cluster.promServiceLabels = promServiceLabels()
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(nil))
	if !strings.Contains(message, "not found") {
		t.Fatalf("deny prometheus:* under partial discovery = %q, want not found", message)
	}
	if cluster.promServiceCalls != 0 {
		t.Fatalf("promServiceCalls = %d, want 0", cluster.promServiceCalls)
	}

	env.srv.policyMu.Lock()
	cached := len(env.srv.policyByKey)
	env.srv.policyMu.Unlock()
	if cached != 0 {
		t.Fatalf("partial-discovery policy was cached (%d entries)", cached)
	}
}

func wrapPartialDiscovery(name string) error {
	return fmt.Errorf("%w: %w: %q", kube.ErrUnknownResource, kube.ErrPartialDiscovery, name)
}

// TestPrometheusQueryTimeoutBoundedByRequestTimeout verifies the effective
// Prometheus timeout is the server default, capped by a provider request_timeout
// override (ADR 0017).
func TestPrometheusQueryTimeoutBoundedByRequestTimeout(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Server.PrometheusTimeout = config.Duration(10 * time.Second)
	cfg.Server.RequestTimeout = config.Duration(30 * time.Second)

	overridden := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	overridden.Providers[0].RequestTimeout = durationPtr(3 * time.Second)

	srv := New(cfg, fakeRegistry{}, nil)
	if got := srv.prometheusQueryTimeout("test"); got != 10*time.Second {
		t.Errorf("prometheusQueryTimeout = %s, want 10s", got)
	}

	srvOver := New(overridden, fakeRegistry{}, nil)
	if got := srvOver.prometheusQueryTimeout("test"); got != 3*time.Second {
		t.Errorf("overridden prometheusQueryTimeout = %s, want 3s", got)
	}
}

func durationPtr(d time.Duration) *config.Duration {
	v := config.Duration(d)
	return &v
}

// TestParsePrometheusTimestampFractionalPreserved verifies fractional seconds
// are accepted and preserved, not silently truncated (M2).
func TestParsePrometheusTimestampFractionalPreserved(t *testing.T) {
	ts, err := parsePrometheusTimestamp("time", "2026-11-19T10:00:00.123456789Z", true)
	if err != nil {
		t.Fatalf("parsePrometheusTimestamp: %v", err)
	}
	if ts.Nanosecond() != 123456789 {
		t.Fatalf("fractional seconds = %d, want 123456789", ts.Nanosecond())
	}
	if _, err := parsePrometheusTimestamp("time", "2026-11-19T10:00:00", true); err == nil {
		t.Fatal("a timestamp without zone must be rejected")
	}
}

// TestPrometheusEnvelopeBudget verifies the final envelope is bounded against
// server.max_response_bytes even when JSON escaping grows the result beyond the
// raw body cap (M1).
func TestPrometheusEnvelopeBudget(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Server.MaxResponseBytes = 256
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promResp = &kube.PrometheusResponse{
		Data: map[string]any{
			"resultType": "vector",
			"result":     []any{map[string]any{"metric": map[string]any{}, "value": []any{"1", strings.Repeat("<>&", 200)}}},
		},
	}
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(nil))
	if !strings.Contains(message, "response too large") {
		t.Fatalf("error = %q, want response too large", message)
	}
	if cluster.promQueryCalls != 1 {
		t.Fatalf("promQueryCalls = %d, want 1 (the budget check is post-fetch)", cluster.promQueryCalls)
	}
}

// TestPrometheusQueryLengthRejectedBeforeCall verifies an over-length query is
// rejected before any cluster traffic (M3b).
func TestPrometheusQueryLengthRejectedBeforeCall(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Server.MaxPrometheusQueryLength = 4
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(map[string]any{"query": strings.Repeat("x", 100)}))
	if !strings.Contains(message, "byte limit") {
		t.Fatalf("error = %q, want the byte limit message", message)
	}
	if cluster.promServiceCalls != 0 || cluster.promQueryCalls != 0 {
		t.Fatalf("API traffic on a rejected query: service=%d query=%d, want 0/0",
			cluster.promServiceCalls, cluster.promQueryCalls)
	}
}

// TestPrometheusQueryRangeSpanLimit verifies a range exceeding
// max_prometheus_query_range is rejected independently of the point limit (M3c).
func TestPrometheusQueryRangeSpanLimit(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbRange)})
	cfg.Server.MaxPrometheusQueryRange = config.Duration(time.Hour)
	cluster := baseCluster()
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query_range", map[string]any{
		"provider": "test", "context": "ctx", "datasource": "main", "query": "up",
		"start": "2026-11-19T09:00:00Z", "end": "2026-11-19T11:00:00Z", "step": "1m",
	})
	if !strings.Contains(message, "range") {
		t.Fatalf("error = %q, want the range-limit message", message)
	}
	if cluster.promServiceCalls != 0 {
		t.Fatalf("promServiceCalls = %d, want 0", cluster.promServiceCalls)
	}
}

// TestPrometheusRedactionCapBreachNotFound verifies a redaction depth/byte cap
// breach on a Prometheus result is fail-closed ("not found"), never returned
// unredacted (M3d).
func TestPrometheusRedactionCapBreachNotFound(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Providers[0].Redactions = []config.RedactionConfig{{
		Resources: []string{"prometheus"},
		Replace:   []config.ReplaceRedaction{{Pattern: "x"}},
	}}
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promResp = &kube.PrometheusResponse{
		Data: map[string]any{"resultType": "vector", "result": nestedObject(70)},
	}
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "not found") {
		t.Fatalf("error = %q, want not found", message)
	}
	if cluster.promQueryCalls != 1 {
		t.Fatalf("promQueryCalls = %d, want 1 (the breach happens after the read)", cluster.promQueryCalls)
	}
}

// TestListConfiguredRulesExposesDatasourceNamesOnly verifies list_configured_rules
// exposes only the Prometheus datasource name (as a plain string), never
// namespace, service or port.
func TestListConfiguredRulesExposesDatasourceNamesOnly(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Providers[0].PolicyRead = true
	env := newTestEnv(t, cfg, baseCluster())

	out := env.callOK("list_configured_rules", nil)
	providers, _ := out["providers"].([]any)
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(providers))
	}
	provider, _ := providers[0].(map[string]any)

	// The datasource name is exposed, as a plain string, in configuration order.
	datasources, _ := provider["datasources"].([]any)
	if len(datasources) != 1 {
		t.Fatalf("datasources = %v, want exactly one name", provider["datasources"])
	}
	if name, ok := datasources[0].(string); !ok || name != "main" {
		t.Fatalf("datasources[0] = %v (%T), want plain string \"main\"", datasources[0], datasources[0])
	}

	// namespace, service and port are never exposed.
	for _, key := range []string{"namespace", "service", "port"} {
		if _, present := provider[key]; present {
			t.Errorf("provider object leaked key %q", key)
		}
	}
	if text := resultText(t, env.call("list_configured_rules", nil)); strings.Contains(text, "prometheus-k8s") || strings.Contains(text, "9090") {
		t.Fatalf("list_configured_rules leaked datasource service/port: %s", text)
	}

	// prometheus:query remains visible verbatim.
	rules, _ := provider["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want 1", provider["rules"])
	}
	rule, _ := rules[0].(map[string]any)
	caps, _ := rule["capabilities"].([]any)
	if len(caps) != 1 {
		t.Fatalf("capabilities = %v, want 1", rule["capabilities"])
	}
	capability, _ := caps[0].(map[string]any)
	if capability["resource"] != "prometheus" || capability["verb"] != "query" {
		t.Errorf("capability = %v, want prometheus:query", capability)
	}
}

// TestListConfiguredRulesDatasourceNamesInConfigOrder verifies datasource names
// are emitted in configuration order, without sorting.
func TestListConfiguredRulesDatasourceNamesInConfigOrder(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Providers[0].PolicyRead = true
	cfg.Providers[0].Prometheus = []config.PrometheusDatasource{
		{Name: "zeta", Namespace: "monitoring", Service: "prom-zeta", Port: 9090},
		{Name: "main", Namespace: "monitoring", Service: "prom-main", Port: 9091},
	}
	env := newTestEnv(t, cfg, baseCluster())

	out := env.callOK("list_configured_rules", nil)
	provider, _ := out["providers"].([]any)[0].(map[string]any)
	datasources, _ := provider["datasources"].([]any)
	if len(datasources) != 2 {
		t.Fatalf("datasources = %v, want 2", provider["datasources"])
	}
	if datasources[0] != "zeta" || datasources[1] != "main" {
		t.Errorf("datasources = %v, want [zeta main] in configuration order", datasources)
	}
}

// TestListConfiguredRulesOmitsProviderWithoutPolicyReadDespiteDatasources
// verifies a provider with datasources but policy_read: false is not listed.
func TestListConfiguredRulesOmitsProviderWithoutPolicyReadDespiteDatasources(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	// policy_read stays false; the datasource must not make the provider visible.
	env := newTestEnv(t, cfg, baseCluster())

	out := env.callOK("list_configured_rules", nil)
	providers, _ := out["providers"].([]any)
	if len(providers) != 0 {
		t.Fatalf("providers = %d, want 0 (policy_read: false hides the provider)", len(providers))
	}
}

// TestListConfiguredRulesOmitsEmptyDatasources verifies a policy_read provider
// without datasources omits the datasources field entirely.
func TestListConfiguredRulesOmitsEmptyDatasources(t *testing.T) {
	cfg := baseConfig([]config.RuleConfig{allowRule([]string{"ns"}, grant("pods", policy.VerbGet))})
	cfg.Providers[0].PolicyRead = true
	env := newTestEnv(t, cfg, baseCluster())

	out := env.callOK("list_configured_rules", nil)
	provider, _ := out["providers"].([]any)[0].(map[string]any)
	if _, present := provider["datasources"]; present {
		t.Error("datasources must be omitted when the provider has no datasources")
	}
}

// TestPrometheusMarkerCheckFailureFailsClosed verifies a namespace-marker check
// failure denies the query (M3g).
func TestPrometheusMarkerCheckFailureFailsClosed(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cfg.Server.NamespaceMarker.Enabled = true
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.markerErr = errors.New("namespaces get forbidden")
	env := newTestEnv(t, cfg, cluster)

	if message := env.callErr("prometheus_query", promQueryArgs(nil)); !strings.Contains(message, "not found") {
		t.Fatalf("error = %q, want not found", message)
	}
	if cluster.promQueryCalls != 0 {
		t.Fatalf("promQueryCalls = %d, want 0", cluster.promQueryCalls)
	}
}

// TestPrometheusCredentialPluginFailure verifies a credential-plugin failure
// during the query maps to the actionable, secret-free hint (M3a).
func TestPrometheusCredentialPluginFailure(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cluster := baseCluster()
	cluster.promServiceLabels = promServiceLabels()
	cluster.promErr = &kube.CredentialError{Plugin: "gcloud"}
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(nil))
	if !strings.Contains(message, "gcloud auth login") {
		t.Fatalf("error = %q, want the gcloud re-authentication hint", message)
	}
	if strings.Contains(message, "exit code") {
		t.Fatalf("error = %q, must not leak plugin output", message)
	}
}

// TestPrometheusServiceErrorMapped verifies a 403 on the Service fetch is
// reported as forbidden (a rights oracle, ADR 0017).
func TestPrometheusServiceForbidden(t *testing.T) {
	cfg := promConfig([]config.RuleConfig{promAllowRule([]string{"monitoring"}, policy.VerbQuery)})
	cluster := baseCluster()
	cluster.promServiceErr = &kube.StatusError{Sentinel: kube.ErrForbidden, Code: 403}
	env := newTestEnv(t, cfg, cluster)

	message := env.callErr("prometheus_query", promQueryArgs(nil))
	if !strings.Contains(message, "forbidden") || !strings.Contains(message, "HTTP 403") {
		t.Fatalf("error = %q, want forbidden with HTTP 403", message)
	}
}

// TestPrometheusSchemaRequiresMandatoryFields checks the tool input schemas.
func TestPrometheusSchemaRequiresMandatoryFields(t *testing.T) {
	env := newTestEnv(t, baseConfig(nil), baseCluster())

	query := toolRequiredFields(t, env, "prometheus_query")
	for _, field := range []string{"provider", "context", "datasource", "query"} {
		if !query[field] {
			t.Errorf("%s is not required in the prometheus_query schema", field)
		}
	}
	if query["time"] {
		t.Error("time must be optional in the prometheus_query schema")
	}

	rng := toolRequiredFields(t, env, "prometheus_query_range")
	for _, field := range []string{"provider", "context", "datasource", "query", "start", "end", "step"} {
		if !rng[field] {
			t.Errorf("%s is not required in the prometheus_query_range schema", field)
		}
	}
}
