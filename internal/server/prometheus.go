package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
)

// prometheusQueryInput is the argument object of the prometheus_query tool.
type prometheusQueryInput struct {
	Provider   string `json:"provider" jsonschema:"logical provider name"`
	Context    string `json:"context" jsonschema:"kubeconfig context; must match the provider's contexts"`
	Datasource string `json:"datasource" jsonschema:"configured Prometheus datasource name (unique per provider)"`
	Query      string `json:"query" jsonschema:"PromQL expression"`
	Time       string `json:"time,omitempty" jsonschema:"RFC3339 evaluation timestamp; defaults to now"`
}

// prometheusRangeInput is the argument object of the prometheus_query_range
// tool.
type prometheusRangeInput struct {
	Provider   string `json:"provider" jsonschema:"logical provider name"`
	Context    string `json:"context" jsonschema:"kubeconfig context; must match the provider's contexts"`
	Datasource string `json:"datasource" jsonschema:"configured Prometheus datasource name (unique per provider)"`
	Query      string `json:"query" jsonschema:"PromQL expression"`
	Start      string `json:"start" jsonschema:"RFC3339 start timestamp (inclusive)"`
	End        string `json:"end" jsonschema:"RFC3339 end timestamp (inclusive)"`
	Step       string `json:"step" jsonschema:"positive Go duration (15s, 1m)"`
}

// prometheusOutput is the response envelope of both Prometheus tools.
type prometheusOutput struct {
	Provider   string   `json:"provider"`
	Context    string   `json:"context"`
	Datasource string   `json:"datasource"`
	ResultType string   `json:"resultType"`
	Result     any      `json:"result"`
	Warnings   []string `json:"warnings,omitempty"`
	Infos      []string `json:"infos,omitempty"`
}

// handlePrometheusQuery implements the prometheus_query tool (ADR 0017).
//
//nolint:gocritic // hugeParam: MCP SDK handler signature
func (s *Server) handlePrometheusQuery(ctx context.Context, _ *mcp.CallToolRequest, in prometheusQueryInput) (*mcp.CallToolResult, any, error) {
	cluster, err := s.resolveRegistry(in.Provider, in.Context)
	if err != nil {
		return nil, nil, err
	}
	ds, err := s.prometheusDatasource(in.Provider, in.Datasource)
	if err != nil {
		return nil, nil, err
	}
	if err = validatePromQL(in.Query, s.cfg.Server.MaxPrometheusQueryLength); err != nil {
		return nil, nil, err
	}
	ts, err := parsePrometheusTimestamp("time", in.Time, false)
	if err != nil {
		return nil, nil, err
	}
	if ts == nil {
		now := time.Now()
		ts = &now
	}

	spec := prometheusRunSpec{
		query: in.Query,
		time:  ts,
	}
	return s.runPrometheus(ctx, cluster, in.Provider, in.Context, ds, policy.VerbQuery, spec)
}

// handlePrometheusQueryRange implements the prometheus_query_range tool
// (ADR 0017).
//
//nolint:gocritic // hugeParam: MCP SDK handler signature
func (s *Server) handlePrometheusQueryRange(ctx context.Context, _ *mcp.CallToolRequest, in prometheusRangeInput) (*mcp.CallToolResult, any, error) {
	cluster, err := s.resolveRegistry(in.Provider, in.Context)
	if err != nil {
		return nil, nil, err
	}
	ds, err := s.prometheusDatasource(in.Provider, in.Datasource)
	if err != nil {
		return nil, nil, err
	}
	if err = validatePromQL(in.Query, s.cfg.Server.MaxPrometheusQueryLength); err != nil {
		return nil, nil, err
	}
	start, err := parsePrometheusTimestamp("start", in.Start, true)
	if err != nil {
		return nil, nil, err
	}
	end, err := parsePrometheusTimestamp("end", in.End, true)
	if err != nil {
		return nil, nil, err
	}
	step, err := parsePrometheusStep(in.Step)
	if err != nil {
		return nil, nil, err
	}
	if end.Before(*start) {
		return nil, nil, errors.New("end must not precede start")
	}
	span := end.Sub(*start)
	if span > time.Duration(s.cfg.Server.MaxPrometheusQueryRange) {
		return nil, nil, fmt.Errorf("range exceeds the %s limit", s.cfg.Server.MaxPrometheusQueryRange)
	}
	points := int64(span/time.Duration(step)) + 1
	if points > int64(s.cfg.Server.MaxPrometheusQueryPoints) {
		return nil, nil, fmt.Errorf("query exceeds the %d point limit (step is too fine for this range)",
			s.cfg.Server.MaxPrometheusQueryPoints)
	}

	spec := prometheusRunSpec{
		query: in.Query,
		rng:   &prometheusRangeSpec{start: *start, end: *end, step: step},
	}
	return s.runPrometheus(ctx, cluster, in.Provider, in.Context, ds, policy.VerbRange, spec)
}

// prometheusRunSpec carries the already-validated query parameters.
type prometheusRunSpec struct {
	query string
	time  *time.Time
	rng   *prometheusRangeSpec
}

// prometheusRangeSpec carries a validated range query's parameters.
type prometheusRangeSpec struct {
	start time.Time
	end   time.Time
	step  time.Duration
}

// runPrometheus is the shared body of both Prometheus tools: pre-check, Service
// fetch, full authorization (labels + namespace marker), proxy call, redaction
// and envelope shaping.
func (s *Server) runPrometheus(
	ctx context.Context,
	cluster Cluster,
	provider, contextName string,
	ds *config.PrometheusDatasource,
	verb policy.Verb,
	spec prometheusRunSpec,
) (*mcp.CallToolResult, any, error) {
	resource := policy.PrometheusResource()

	compiled, err := s.policyFor(ctx, provider, contextName, cluster)
	if err != nil {
		return nil, nil, err
	}
	proceed, reason := compiled.PreCheck(&policy.Request{
		Namespace:  ds.Namespace,
		Namespaced: true,
		Resource:   resource,
		Verb:       verb,
		Name:       ds.Name,
	})
	if !proceed {
		s.logger.Info("prometheus denied by pre-check",
			"provider", provider, "context", contextName, "resource", resource.String(),
			"verb", string(verb), "namespace", ds.Namespace, "datasource", ds.Name, "reason", reason)
		return nil, nil, errNotFound
	}

	wire := kube.PrometheusDatasource{Namespace: ds.Namespace, Service: ds.Service, Port: ds.Port}
	labels, err := cluster.PrometheusService(ctx, wire)
	if err != nil {
		return nil, nil, mapKubeError(err)
	}

	decision := compiled.Evaluate(&policy.Request{
		Namespace:  ds.Namespace,
		Namespaced: true,
		Resource:   resource,
		Verb:       verb,
		Name:       ds.Name,
		Labels:     policy.LabelSet{Known: true, Values: labels},
	})
	if !decision.Allowed {
		s.logger.Info("prometheus denied",
			"provider", provider, "context", contextName, "resource", resource.String(),
			"verb", string(verb), "namespace", ds.Namespace, "datasource", ds.Name, "reason", decision.Reason)
		return nil, nil, errNotFound
	}

	if s.markerEnabled() && !decision.NamespaceMarkerExempt {
		marked, markerErr := cluster.NamespaceMarked(ctx, ds.Namespace, s.markerLabel())
		if markerErr != nil {
			s.logger.Error("prometheus namespace marker check failed; denying",
				"provider", provider, "context", contextName,
				"namespace", ds.Namespace, "error", markerErr.Error())
			return nil, nil, errNotFound
		}
		if marked {
			s.logger.Info("prometheus denied by namespace marker",
				"provider", provider, "context", contextName,
				"namespace", ds.Namespace, "datasource", ds.Name)
			return nil, nil, errNotFound
		}
	}

	engine, err := s.redactionFor(ctx, provider, contextName, cluster)
	if err != nil {
		return nil, nil, err
	}

	timeout := s.prometheusQueryTimeout(provider)
	response, err := s.prometheusCall(ctx, cluster, wire, verb, spec, timeout)
	if err != nil {
		return nil, nil, s.mapPrometheusError(err)
	}

	redacted, err := engine.ApplyObject(response.Data,
		redactionMatch(resource, ds.Namespace, true, ds.Name, labels))
	if err != nil {
		// A cap breach fails closed: the result is never returned unredacted.
		s.logger.Error("prometheus redaction failed; denying",
			"provider", provider, "context", contextName, "resource", resource.String(),
			"namespace", ds.Namespace, "datasource", ds.Name)
		return nil, nil, errNotFound
	}

	out := prometheusOutput{
		Provider:   provider,
		Context:    contextName,
		Datasource: ds.Name,
		ResultType: stringField(redacted, "resultType"),
		Result:     redacted["result"],
		Warnings:   response.Warnings,
		Infos:      response.Infos,
	}
	// The decoded body cap is not the whole-response budget: json.Marshal
	// escapes HTML characters (`<`, `>`, `&`) and can grow the envelope. Check
	// the actually serialized size and fail closed on an over-budget envelope
	// (ADR 0013, ADR 0017).
	if marshalSize(out) > s.cfg.Server.MaxResponseBytes {
		s.logger.Error("prometheus response exceeds budget; failing closed",
			"provider", provider, "context", contextName,
			"namespace", ds.Namespace, "datasource", ds.Name)
		return nil, nil, errors.New("query failed (response too large)")
	}
	return jsonResult(out)
}

// prometheusCall invokes the kube layer for the instant or range query.
func (s *Server) prometheusCall(
	ctx context.Context,
	cluster Cluster,
	wire kube.PrometheusDatasource,
	verb policy.Verb,
	spec prometheusRunSpec,
	timeout time.Duration,
) (*kube.PrometheusResponse, error) {
	if verb == policy.VerbQuery {
		return cluster.PrometheusQuery(ctx, wire, kube.PrometheusQueryParams{
			Query:            spec.query,
			Time:             spec.time,
			Timeout:          timeout,
			MaxResponseBytes: int64(s.cfg.Server.MaxPrometheusResponseBytes),
		})
	}
	return cluster.PrometheusQueryRange(ctx, wire, kube.PrometheusRangeParams{
		Query:            spec.query,
		Start:            spec.rng.start,
		End:              spec.rng.end,
		Step:             spec.rng.step,
		Timeout:          timeout,
		MaxResponseBytes: int64(s.cfg.Server.MaxPrometheusResponseBytes),
	})
}

// prometheusDatasource resolves a configured datasource name for a provider. An
// unknown name is a configuration error (ADR 0017), not an object-existence
// oracle.
func (s *Server) prometheusDatasource(provider, name string) (*config.PrometheusDatasource, error) {
	p, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
	for i := range p.Prometheus {
		if p.Prometheus[i].Name == name {
			return &p.Prometheus[i], nil
		}
	}
	return nil, fmt.Errorf("unknown datasource %q for provider %q", name, provider)
}

// prometheusQueryTimeout returns the effective Prometheus timeout for a provider:
// the server default, bounded by that provider's request_timeout (ADR 0017).
func (s *Server) prometheusQueryTimeout(provider string) time.Duration {
	timeout := time.Duration(s.cfg.Server.PrometheusTimeout)
	if p, ok := s.providers[provider]; ok && p.RequestTimeout != nil {
		if d := time.Duration(*p.RequestTimeout); d > 0 && d < timeout {
			timeout = d
		}
	} else if d := time.Duration(s.cfg.Server.RequestTimeout); d > 0 && d < timeout {
		timeout = d
	}
	return timeout
}

// mapPrometheusError maps a proxy-query error to a safe message (ADR 0017). The
// raw upstream body is never returned.
func (s *Server) mapPrometheusError(err error) error {
	switch {
	case errors.Is(err, kube.ErrPrometheusBusy):
		return errors.New("prometheus query concurrency limit reached; retry shortly")
	case errors.Is(err, kube.ErrPrometheusTimeout):
		return errors.New("query failed (timeout)")
	case errors.Is(err, kube.ErrPrometheusResponseTooLarge):
		return errors.New("query failed (response too large)")
	case errors.Is(err, kube.ErrPrometheusInvalid):
		if perr, ok := errPrometheusError(err); ok {
			if perr.Message != "" {
				return fmt.Errorf("query failed (invalid): %s (errorType %s)", perr.Message, perr.ErrorType)
			}
			return fmt.Errorf("query failed (invalid) (errorType %s)", perr.ErrorType)
		}
		return errors.New("query failed (invalid)")
	case errors.Is(err, kube.ErrPrometheusUpstream):
		return errors.New("query failed (upstream)")
	default:
		return mapKubeError(err)
	}
}

func errPrometheusError(err error) (*kube.PrometheusError, bool) {
	var perr *kube.PrometheusError
	if errors.As(err, &perr) {
		return perr, true
	}
	return nil, false
}

// validatePromQL rejects an empty, overlong or control-character PromQL query.
func validatePromQL(query string, maxLen int) error {
	if query == "" {
		return errors.New("query must not be empty")
	}
	if len(query) > maxLen {
		return fmt.Errorf("query exceeds the %d byte limit", maxLen)
	}
	return rejectControlChars("query", query)
}

// parsePrometheusTimestamp parses a strict RFC 3339 timestamp. required selects
// whether an empty value is an error; when allowed, an empty value returns nil.
// Fractional seconds are accepted and preserved (RFC3339Nano), matching RFC 3339
// section 5.6.
func parsePrometheusTimestamp(field, value string, required bool) (*time.Time, error) {
	if value == "" {
		if required {
			return nil, fmt.Errorf("%s must not be empty", field)
		}
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be a strict RFC3339 timestamp", field)
	}
	return &t, nil
}

// parsePrometheusStep parses a strict positive Go duration.
func parsePrometheusStep(value string) (time.Duration, error) {
	if value == "" {
		return 0, errors.New("step must not be empty")
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, errors.New("step must be a positive Go duration")
	}
	return d, nil
}

// stringField returns field of m as a string, or "" when absent or not a string.
func stringField(m map[string]any, field string) string {
	s, _ := m[field].(string)
	return s
}
