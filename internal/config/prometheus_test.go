package config

import (
	"strings"
	"testing"
	"time"

	"github.com/haininghu/mcp-keel/internal/policy"
)

func TestParsePrometheusDefaults(t *testing.T) {
	cfg, err := Parse([]byte(goodConfig))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	s := cfg.Server
	if s.MaxPrometheusQueryLength != defaultMaxPrometheusQueryLength {
		t.Errorf("MaxPrometheusQueryLength = %d, want %d", s.MaxPrometheusQueryLength, defaultMaxPrometheusQueryLength)
	}
	if s.MaxPrometheusQueryRange != Duration(defaultMaxPrometheusQueryRange) {
		t.Errorf("MaxPrometheusQueryRange = %s, want %s", s.MaxPrometheusQueryRange, Duration(defaultMaxPrometheusQueryRange))
	}
	if s.MaxPrometheusQueryPoints != defaultMaxPrometheusQueryPoints {
		t.Errorf("MaxPrometheusQueryPoints = %d, want %d", s.MaxPrometheusQueryPoints, defaultMaxPrometheusQueryPoints)
	}
	if s.MaxPrometheusResponseBytes != defaultMaxPrometheusResponseBytes {
		t.Errorf("MaxPrometheusResponseBytes = %d, want %d", s.MaxPrometheusResponseBytes, defaultMaxPrometheusResponseBytes)
	}
	if s.PrometheusTimeout != Duration(defaultPrometheusTimeout) {
		t.Errorf("PrometheusTimeout = %s, want %s", s.PrometheusTimeout, Duration(defaultPrometheusTimeout))
	}
	if s.MaxPrometheusConcurrency != defaultMaxPrometheusConcurrency {
		t.Errorf("MaxPrometheusConcurrency = %d, want %d", s.MaxPrometheusConcurrency, defaultMaxPrometheusConcurrency)
	}
}

func TestParsePrometheusExplicitDefaults(t *testing.T) {
	input := strings.Replace(goodConfig, "log_level: info", `log_level: info
  max_prometheus_query_length: 65536
  max_prometheus_query_range: 168h
  max_prometheus_query_points: 11000
  max_prometheus_response_bytes: 8388608
  prometheus_timeout: 30s
  max_prometheus_concurrency: 32`, 1)
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	s := cfg.Server
	if s.MaxPrometheusQueryLength != 65536 || s.MaxPrometheusQueryRange != Duration(7*24*time.Hour) ||
		s.MaxPrometheusQueryPoints != 11000 || s.MaxPrometheusResponseBytes != 8<<20 ||
		s.PrometheusTimeout != Duration(30*time.Second) || s.MaxPrometheusConcurrency != 32 {
		t.Errorf("explicit limits = %+v", s)
	}
}

func TestParsePrometheusInvalidLimits(t *testing.T) {
	cases := map[string]string{
		"query length zero": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_query_length: 0", 1),
		"query length too big": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_query_length: 65537", 1),
		"query range zero": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_query_range: 0s", 1),
		"query range too big": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_query_range: 168h1s", 1),
		"points zero": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_query_points: 0", 1),
		"points too big": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_query_points: 11001", 1),
		"response bytes zero": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_response_bytes: 0", 1),
		"response bytes exceeds budget": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_response_bytes: 1000000\n  max_prometheus_response_bytes: 1000001", 1),
		"response bytes exceeds hard cap": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_response_bytes: 16777216\n  max_prometheus_response_bytes: 8388609", 1),
		"timeout zero": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  prometheus_timeout: 0s", 1),
		"concurrency zero": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_concurrency: 0", 1),
		"concurrency too big": strings.Replace(goodConfig, "log_level: info",
			"log_level: info\n  max_prometheus_concurrency: 33", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want an error\n---\n%s", input)
			}
		})
	}
}

func TestParsePrometheusDatasource(t *testing.T) {
	input := `version: 1
providers:
  - name: p
    contexts: ["*"]
    rules: []
    prometheus:
      - name: main
        namespace: monitoring
        service: prometheus-k8s
        port: 9090
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ds := cfg.Providers[0].Prometheus
	if len(ds) != 1 {
		t.Fatalf("len(Prometheus) = %d, want 1", len(ds))
	}
	if ds[0].Name != "main" || ds[0].Namespace != "monitoring" || ds[0].Service != "prometheus-k8s" || ds[0].Port != 9090 {
		t.Errorf("datasource = %+v", ds[0])
	}
}

func TestParsePrometheusDatasourceInvalid(t *testing.T) {
	cases := map[string]string{
		"empty name":     "name: \"\"\n    namespace: monitoring\n    service: prometheus-k8s\n    port: 9090",
		"uppercase name": "name: Main\n    namespace: monitoring\n    service: prometheus-k8s\n    port: 9090",
		"bad namespace":  "name: main\n    namespace: \"Bad NS\"\n    service: prometheus-k8s\n    port: 9090",
		"bad service":    "name: main\n    namespace: monitoring\n    service: \"prometheus k8s\"\n    port: 9090",
		"port zero":      "name: main\n    namespace: monitoring\n    service: prometheus-k8s\n    port: 0",
		"port too big":   "name: main\n    namespace: monitoring\n    service: prometheus-k8s\n    port: 65536",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			input := "version: 1\nproviders:\n  - name: p\n    contexts: [\"*\"]\n    rules: []\n    prometheus:\n      - " +
				strings.ReplaceAll(body, "\n", "\n        ")
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want an error\n---\n%s", input)
			}
		})
	}
}

func TestParsePrometheusDatasourceDuplicateName(t *testing.T) {
	input := `version: 1
providers:
  - name: p
    contexts: ["*"]
    rules: []
    prometheus:
      - name: main
        namespace: monitoring
        service: prometheus-k8s
        port: 9090
      - name: main
        namespace: other
        service: prometheus-k8s
        port: 9090
`
	if _, err := Parse([]byte(input)); err == nil {
		t.Fatal("Parse() error = nil, want a duplicate-name error")
	}
}

func TestParsePrometheusCapabilities(t *testing.T) {
	// prometheus:query and prometheus:range are valid on allow rules.
	allow := strings.Replace(goodConfig, "- core/pods:get", "- prometheus:query\n          - prometheus:range", 1)
	if _, err := Parse([]byte(allow)); err != nil {
		t.Errorf("prometheus:query/range on allow: Parse() error = %v", err)
	}

	// prometheus:* is valid on a deny rule.
	deny := strings.Replace(goodConfig, "effect: allow", "effect: deny", 1)
	deny = strings.Replace(deny, "- core/pods:get", "- prometheus:*", 1)
	if _, err := Parse([]byte(deny)); err != nil {
		t.Errorf("prometheus:* on deny: Parse() error = %v", err)
	}
}

func TestParsePrometheusCapabilityRejected(t *testing.T) {
	cases := map[string]string{
		"star query":      strings.Replace(goodConfig, "- core/pods:get", "- \"*:query\"", 1),
		"star range":      strings.Replace(goodConfig, "- core/pods:get", "- \"*:range\"", 1),
		"group query":     strings.Replace(goodConfig, "- core/pods:get", "- \"core/prometheus:query\"", 1),
		"subresource":     strings.Replace(goodConfig, "- core/pods:get", "- \"prometheus/log:query\"", 1),
		"query wrong res": strings.Replace(goodConfig, "- core/pods:get", "- \"pods:query\"", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want an error\n---\n%s", input)
			}
		})
	}
}

func TestParsePrometheusGetListThroughDiscovery(t *testing.T) {
	// prometheus:get and prometheus:list keep their discovery meaning.
	input := strings.Replace(goodConfig, "- core/pods:get", "- prometheus:get\n          - prometheus:list", 1)
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	grant := cfg.Providers[0].Rules[0].Capabilities[0]
	if grant.Resource != "prometheus" || grant.Verb != policy.VerbGet {
		t.Errorf("capability = %+v, want prometheus:get", grant)
	}
}
