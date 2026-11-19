package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// Prometheus request bounds. They are defensive, hard upper limits enforced in
// this package independently of the server configuration (ADR 0017).
const (
	// maxPrometheusQueryBytes is the hard bound on a Prometheus query string.
	maxPrometheusQueryBytes = 64 << 10
	// maxPrometheusErrorBytes bounds a sanitized Prometheus error payload that
	// is surfaced to the caller.
	maxPrometheusErrorBytes = 2 << 10
	// maxPrometheusWarningEntries bounds each of the warnings/infos lists.
	maxPrometheusWarningEntries = 16
	// maxPrometheusWarningEntryBytes bounds a single warning/info string.
	maxPrometheusWarningEntryBytes = 512
)

const (
	prometheusQueryEndpoint      = "api/v1/query"
	prometheusQueryRangeEndpoint = "api/v1/query_range"
)

// PrometheusDatasource is the wire identity of a configured Prometheus
// datasource: the Service (and its validated port) to reach through the API
// server proxy (ADR 0017). The name is not needed here; it is resolved by the
// server for policy matching.
type PrometheusDatasource struct {
	Namespace string
	Service   string
	Port      int
}

// PrometheusQueryParams selects and bounds a single instant query. The fields
// are already validated by the server; Timeout is server-set and MaxResponseBytes
// is the decoded body budget, capped by the server config.
type PrometheusQueryParams struct {
	Query            string
	Time             *time.Time
	Timeout          time.Duration
	MaxResponseBytes int64
}

// PrometheusRangeParams selects and bounds a single range query.
type PrometheusRangeParams struct {
	Query            string
	Start            time.Time
	End              time.Time
	Step             time.Duration
	Timeout          time.Duration
	MaxResponseBytes int64
}

// PrometheusResponse is one decoded, bounded Prometheus query response. Data is
// the decoded "data" object (resultType string, result JSON value); numbers are
// decoded with json.Number so values above 2^53 survive (ADR 0017).
type PrometheusResponse struct {
	Data     map[string]any
	Warnings []string
	Infos    []string
}

// newPrometheusHTTPClient builds an *http.Client using the config's transport
// (credentials, exec plugin, TLS, request timeout) but with redirects rejected:
// a redirect could send the API-server bearer token to another host (ADR 0017).
func newPrometheusHTTPClient(cfg *rest.Config) (*http.Client, error) {
	transport, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// PrometheusService fetches the configured Service and confirms that the
// datasource's numeric port is exposed. It returns the Service's labels for the
// policy decision; the Service object itself is never returned. A missing Service
// and a Service without the configured port are both reported as ErrNotFound
// (existence is hidden, ADR 0017).
func (c *Cluster) PrometheusService(ctx context.Context, ds PrometheusDatasource) (map[string]string, error) {
	if err := validatePrometheusDatasource(ds); err != nil {
		return nil, err
	}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
	obj, err := c.dynamic.Resource(gvr).Namespace(ds.Namespace).Get(ctx, ds.Service, metav1.GetOptions{})
	if err != nil {
		return nil, c.safeAPIError(err)
	}
	if obj == nil {
		return nil, ErrNotFound
	}
	if !serviceExposesPort(obj, ds.Port) {
		return nil, ErrNotFound
	}
	return obj.GetLabels(), nil
}

// PrometheusQuery evaluates a PromQL expression at a single instant through the
// Kubernetes service proxy. It acquires the per-provider concurrency slot,
// bounds the whole request (including the body read) by a context deadline,
// builds exactly GET {service}:{port}/proxy/api/v1/query and returns the decoded
// response (ADR 0017).
func (c *Cluster) PrometheusQuery(ctx context.Context, ds PrometheusDatasource, params PrometheusQueryParams) (*PrometheusResponse, error) {
	if err := c.acquirePrometheus(); err != nil {
		return nil, err
	}
	defer c.releasePrometheus()

	if err := validatePrometheusDatasource(ds); err != nil {
		return nil, err
	}
	if err := validatePrometheusQuery(params.Query); err != nil {
		return nil, err
	}
	if params.Timeout <= 0 {
		return nil, errors.New("kube: prometheus timeout must be positive")
	}
	if params.MaxResponseBytes < 0 {
		return nil, errors.New("kube: prometheus response budget must not be negative")
	}

	values := url.Values{}
	values.Set("query", params.Query)
	if params.Time != nil {
		values.Set("time", params.Time.Format(time.RFC3339Nano))
	}
	values.Set("timeout", params.Timeout.String())

	return c.prometheusGet(ctx, ds, prometheusQueryEndpoint, values, params.Timeout, params.MaxResponseBytes)
}

// PrometheusQueryRange evaluates a PromQL expression over [start, end] every step.
func (c *Cluster) PrometheusQueryRange(ctx context.Context, ds PrometheusDatasource, params PrometheusRangeParams) (*PrometheusResponse, error) {
	if err := c.acquirePrometheus(); err != nil {
		return nil, err
	}
	defer c.releasePrometheus()

	if err := validatePrometheusDatasource(ds); err != nil {
		return nil, err
	}
	if err := validatePrometheusQuery(params.Query); err != nil {
		return nil, err
	}
	if params.Timeout <= 0 {
		return nil, errors.New("kube: prometheus timeout must be positive")
	}
	if params.MaxResponseBytes < 0 {
		return nil, errors.New("kube: prometheus response budget must not be negative")
	}
	if params.Start.IsZero() || params.End.IsZero() {
		return nil, errors.New("kube: prometheus range requires start and end")
	}
	if params.Step <= 0 {
		return nil, errors.New("kube: prometheus step must be positive")
	}
	if params.End.Before(params.Start) {
		return nil, errors.New("kube: prometheus range end must not precede start")
	}

	values := url.Values{}
	values.Set("query", params.Query)
	values.Set("start", params.Start.Format(time.RFC3339Nano))
	values.Set("end", params.End.Format(time.RFC3339Nano))
	values.Set("step", params.Step.String())
	values.Set("timeout", params.Timeout.String())

	return c.prometheusGet(ctx, ds, prometheusQueryRangeEndpoint, values, params.Timeout, params.MaxResponseBytes)
}

// acquirePrometheus takes a slot from the per-provider concurrency sink without
// blocking: an excess query is rejected immediately, never queued (ADR 0017).
func (c *Cluster) acquirePrometheus() error {
	if c.promSlots == nil {
		return nil
	}
	select {
	case c.promSlots <- struct{}{}:
		return nil
	default:
		return ErrPrometheusBusy
	}
}

// releasePrometheus returns a slot acquired by acquirePrometheus.
func (c *Cluster) releasePrometheus() {
	if c.promSlots != nil {
		<-c.promSlots
	}
}

// prometheusGet performs the bounded proxy GET and decodes the response. Agent
// inputs are encoded exclusively through url.Values; path segments come only
// from validated configuration.
func (c *Cluster) prometheusGet(ctx context.Context, ds PrometheusDatasource, endpoint string, values url.Values, timeout time.Duration, cap int64) (*PrometheusResponse, error) {
	if c.logs == nil || c.promHTTP == nil {
		return nil, errors.New("kube: prometheus client is not configured")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := c.logs.Get().
		Namespace(ds.Namespace).
		Resource("services").
		SubResource("proxy").
		Name(ds.Service + ":" + strconv.Itoa(ds.Port)).
		Suffix(endpoint)
	for key, vs := range values {
		for _, v := range vs {
			req = req.Param(key, v)
		}
	}
	if err := req.Error(); err != nil {
		return nil, c.classifyPrometheusErr(err)
	}
	httpReq, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, req.URL().String(), nil)
	if err != nil {
		return nil, c.classifyPrometheusErr(err)
	}

	resp, err := c.promHTTP.Do(httpReq)
	if err != nil {
		return nil, c.classifyPrometheusErr(err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// A redirect must never be followed; it is an error (ADR 0017).
		return nil, ErrPrometheusUpstream
	case resp.StatusCode == http.StatusForbidden:
		return nil, &StatusError{Sentinel: ErrForbidden, Code: resp.StatusCode}
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, &StatusError{Sentinel: ErrUnauthorized, Code: resp.StatusCode}
	case resp.StatusCode == http.StatusNotFound:
		// The Service was deleted between the fetch and the query.
		return nil, ErrNotFound
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, ErrPrometheusUpstream
	}

	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		return nil, ErrPrometheusUpstream
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, cap+1))
	if readErr != nil {
		return nil, c.classifyPrometheusErr(readErr)
	}
	if int64(len(body)) > cap {
		return nil, ErrPrometheusResponseTooLarge
	}
	return parsePrometheusResponse(body)
}

// classifyPrometheusErr maps a transport-level error (or a malformed request) to
// a sentinel, preserving a credential-plugin failure as a CredentialError.
func (c *Cluster) classifyPrometheusErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrPrometheusTimeout
	}
	if c.credentialPlugin != "" && isCredentialPluginError(err) {
		return &CredentialError{Plugin: c.credentialPlugin}
	}
	return ErrPrometheusUpstream
}

// isJSONContentType reports whether the response Content-Type is the JSON media
// type; only such responses are parsed (ADR 0017).
func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "application/json")
}

// parsePrometheusResponse decodes a bounded Prometheus JSON body with json.Number
// and either returns the data object or a sanitized PrometheusError.
func parsePrometheusResponse(body []byte) (*PrometheusResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		return nil, ErrPrometheusUpstream
	}
	if status, _ := doc["status"].(string); status == "error" {
		return nil, prometheusError(doc)
	}
	data, _ := doc["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	return &PrometheusResponse{
		Data:     data,
		Warnings: sanitizePrometheusList(doc["warnings"]),
		Infos:    sanitizePrometheusList(doc["infos"]),
	}, nil
}

// prometheusError extracts and sanitizes the Prometheus error payload.
func prometheusError(doc map[string]any) *PrometheusError {
	return &PrometheusError{
		ErrorType: sanitizePrometheusText(stringValue(doc["errorType"]), maxPrometheusErrorBytes),
		Message:   sanitizePrometheusText(stringValue(doc["error"]), maxPrometheusErrorBytes),
	}
}

// sanitizePrometheusList caps and strips the warnings/infos lists.
func sanitizePrometheusList(value any) []string {
	list, _ := value.([]any)
	if len(list) == 0 {
		return nil
	}
	out := make([]string, 0, minInt(len(list), maxPrometheusWarningEntries))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, sanitizePrometheusText(s, maxPrometheusWarningEntryBytes))
			if len(out) >= maxPrometheusWarningEntries {
				break
			}
		}
	}
	return out
}

// sanitizePrometheusText strips control characters and caps the byte length on a
// UTF-8 boundary.
func sanitizePrometheusText(s string, max int) string {
	s = stripControlChars(s)
	if max >= 0 && len(s) > max {
		s = utf8PrefixBytes(s, max)
	}
	return s
}

// stringValue returns s as a string when it is one, else "".
func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

// stripControlChars removes NUL, C0 controls and DEL from s.
func stripControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0 || r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() == len(s) {
		return s
	}
	return b.String()
}

// utf8PrefixBytes returns the longest prefix of s of at most n bytes ending on a
// UTF-8 rune boundary.
func utf8PrefixBytes(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// validatePrometheusQuery rejects an empty, too-long or control-character query
// string (ADR 0017).
func validatePrometheusQuery(query string) error {
	if query == "" {
		return errors.New("kube: prometheus query must not be empty")
	}
	if len(query) > maxPrometheusQueryBytes {
		return fmt.Errorf("kube: prometheus query exceeds %d bytes", maxPrometheusQueryBytes)
	}
	if containsControlChars(query) {
		return errors.New("kube: prometheus query contains control characters")
	}
	return nil
}

// validatePrometheusDatasource rejects a datasource with empty or malformed wire
// fields. The full validation happens at config load; this is defense in depth
// before a path segment is built from the values.
func validatePrometheusDatasource(ds PrometheusDatasource) error {
	if ds.Port < 1 || ds.Port > 65535 {
		return errors.New("kube: invalid prometheus datasource port")
	}
	if len(validation.IsDNS1123Label(ds.Namespace)) != 0 {
		return errors.New("kube: invalid prometheus datasource namespace")
	}
	if len(validation.IsDNS1123Subdomain(ds.Service)) != 0 {
		return errors.New("kube: invalid prometheus datasource service")
	}
	return nil
}

// serviceExposesPort reports whether obj's spec.ports lists the given numeric
// port.
func serviceExposesPort(obj *unstructured.Unstructured, port int) bool {
	ports, found, err := unstructured.NestedSlice(obj.Object, "spec", "ports")
	if err != nil || !found {
		return false
	}
	for _, p := range ports {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		switch n := m["port"].(type) {
		case int64:
			if int(n) == port {
				return true
			}
		case int:
			if n == port {
				return true
			}
		case float64:
			if n == float64(port) {
				return true
			}
		}
	}
	return false
}

// containsControlChars reports whether s contains NUL, C0 controls or DEL.
func containsControlChars(s string) bool {
	for _, r := range s {
		if r == 0 || r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
