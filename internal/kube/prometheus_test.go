package kube

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
)

// prometheusRequest is what a test proxy endpoint observed, handed over a
// channel so the test reads it without racing the handler goroutine.
type prometheusRequest struct {
	path  string
	query url.Values
}

func newPrometheusTestCluster(t *testing.T, handler http.HandlerFunc, concurrency int) *Cluster {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	logClient, err := newLogClient(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("newLogClient: %v", err)
	}
	httpClient, err := newPrometheusHTTPClient(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("newPrometheusHTTPClient: %v", err)
	}
	return &Cluster{logs: logClient, promHTTP: httpClient, promSlots: make(chan struct{}, concurrency)}
}

// dynamicClientWithService builds a dynamic fake holding one Service that
// exposes port 9090, for the PrometheusService tests.
func dynamicClientWithService(t *testing.T) *dynamicfake.FakeDynamicClient {
	t.Helper()
	svc := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "prometheus-k8s",
			"namespace": "monitoring",
			"labels":    map[string]any{"app": "prometheus"},
		},
		"spec": map[string]any{
			"ports": []any{map[string]any{"port": int64(9090), "protocol": "TCP"}},
		},
	}}
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), svc)
}

func testDatasource() PrometheusDatasource {
	return PrometheusDatasource{Namespace: "monitoring", Service: "prometheus-k8s", Port: 9090}
}

const successVector = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","job":"prometheus"},"value":[1456789000.123456789,"1"]}]}}`

const successMatrix = `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"up"},"values":[[1456789000.123456789012345678,"1"],[1456789001.5,"0"]]}]},"warnings":["w\u0007arn"],"infos":["note"]}`

func TestPrometheusQueryRequest(t *testing.T) {
	requests := make(chan prometheusRequest, 1)
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, r *http.Request) {
		requests <- prometheusRequest{path: r.URL.Path, query: r.URL.Query()}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(successVector))
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query:            "up",
		Time:             timePtr(time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)),
		Timeout:          10 * time.Second,
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("PrometheusQuery: %v", err)
	}

	req := <-requests
	if want := "/api/v1/namespaces/monitoring/services/prometheus-k8s:9090/proxy/api/v1/query"; req.path != want {
		t.Fatalf("request path = %q, want %q", req.path, want)
	}
	if got := req.query.Get("query"); got != "up" {
		t.Errorf("query = %q, want up", got)
	}
	if got := req.query.Get("time"); got != "2026-11-19T10:00:00Z" {
		t.Errorf("time = %q, want RFC3339", got)
	}
	if got := req.query.Get("timeout"); got != "10s" {
		t.Errorf("timeout = %q, want the server-set 10s", got)
	}
	for _, key := range []string{"stats", "lookback_delta", "limit", "max_series", "url", "path"} {
		if req.query.Has(key) {
			t.Errorf("query %s = %q, want it absent", key, req.query.Get(key))
		}
	}
}

func TestPrometheusQueryRangeRequest(t *testing.T) {
	requests := make(chan prometheusRequest, 1)
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, r *http.Request) {
		requests <- prometheusRequest{path: r.URL.Path, query: r.URL.Query()}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(successMatrix))
	}, 1)

	_, err := cluster.PrometheusQueryRange(context.Background(), testDatasource(), PrometheusRangeParams{
		Query:            "rate(http_requests_total[5m])",
		Start:            time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC),
		End:              time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC),
		Step:             time.Minute,
		Timeout:          10 * time.Second,
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("PrometheusQueryRange: %v", err)
	}

	req := <-requests
	if want := "/api/v1/namespaces/monitoring/services/prometheus-k8s:9090/proxy/api/v1/query_range"; req.path != want {
		t.Fatalf("request path = %q, want %q", req.path, want)
	}
	if got := req.query.Get("query"); got != "rate(http_requests_total[5m])" {
		t.Errorf("query = %q", got)
	}
	if got := req.query.Get("start"); got != "2026-11-19T09:00:00Z" {
		t.Errorf("start = %q", got)
	}
	if got := req.query.Get("end"); got != "2026-11-19T10:00:00Z" {
		t.Errorf("end = %q", got)
	}
	if got := req.query.Get("step"); got != "1m0s" {
		t.Errorf("step = %q, want 1m0s", got)
	}
}

func TestPrometheusQueryRangeRejectsInvalid(t *testing.T) {
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("unexpected request")
	}, 1)

	base := PrometheusRangeParams{
		Query:            "up",
		Start:            time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC),
		End:              time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC),
		Step:             time.Minute,
		Timeout:          time.Second,
		MaxResponseBytes: 1 << 20,
	}
	cases := []struct {
		name   string
		mutate func(*PrometheusRangeParams)
	}{
		{name: "end before start", mutate: func(p *PrometheusRangeParams) { p.Start = p.End.Add(time.Hour) }},
		{name: "zero step", mutate: func(p *PrometheusRangeParams) { p.Step = 0 }},
		{name: "zero start", mutate: func(p *PrometheusRangeParams) { p.Start = time.Time{} }},
		{name: "zero end", mutate: func(p *PrometheusRangeParams) { p.End = time.Time{} }},
		{name: "empty query", mutate: func(p *PrometheusRangeParams) { p.Query = "" }},
		{name: "control chars", mutate: func(p *PrometheusRangeParams) { p.Query = "up\x00" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := base
			tc.mutate(&params)
			if _, err := cluster.PrometheusQueryRange(context.Background(), testDatasource(), params); err == nil {
				t.Fatal("expected an error for invalid range parameters")
			}
		})
	}
}

func TestPrometheusQueryRedirectRejected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("a redirect must never be followed")
	}))
	defer target.Close()

	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/leak", http.StatusFound)
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
	})
	if !errors.Is(err, ErrPrometheusUpstream) {
		t.Fatalf("error = %v, want ErrPrometheusUpstream for a redirect", err)
	}
}

func TestPrometheusResponseTooLarge(t *testing.T) {
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":["` + string(make([]byte, 1000)) + `"]}}`))
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: time.Second, MaxResponseBytes: 10,
	})
	if !errors.Is(err, ErrPrometheusResponseTooLarge) {
		t.Fatalf("error = %v, want ErrPrometheusResponseTooLarge", err)
	}
}

func TestPrometheusNonJSONRejected(t *testing.T) {
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("not json"))
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
	})
	if !errors.Is(err, ErrPrometheusUpstream) {
		t.Fatalf("error = %v, want ErrPrometheusUpstream for non-JSON", err)
	}
}

func TestPrometheusStatusErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		want   error
		status int
	}{
		{name: "forbidden", code: http.StatusForbidden, want: ErrForbidden, status: http.StatusForbidden},
		{name: "redirect 302", code: http.StatusFound, want: ErrPrometheusUpstream},
		{name: "server error", code: http.StatusInternalServerError, want: ErrPrometheusUpstream},
		{name: "not found", code: http.StatusNotFound, want: ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
			}, 1)
			_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
				Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if got := HTTPStatus(err); got != tc.status {
				t.Fatalf("HTTPStatus = %d, want %d", got, tc.status)
			}
		})
	}
}

func TestPrometheusJSONNumber(t *testing.T) {
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(successMatrix))
	}, 1)

	resp, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Time: timePtr(time.Now()), Timeout: time.Second, MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("PrometheusQuery: %v", err)
	}
	result, _ := resp.Data["result"].([]any)
	series, _ := result[0].(map[string]any)
	values, _ := series["values"].([]any)
	sample, _ := values[0].([]any)
	if _, ok := sample[0].(json.Number); !ok {
		t.Fatalf("timestamp type = %T, want json.Number", sample[0])
	}
	// Sanitized warnings: control chars stripped.
	if len(resp.Warnings) != 1 || resp.Warnings[0] != "warn" {
		t.Errorf("warnings = %v, want [warn] (control chars stripped)", resp.Warnings)
	}
	if len(resp.Infos) != 1 || resp.Infos[0] != "note" {
		t.Errorf("infos = %v, want [note]", resp.Infos)
	}
}

func TestPrometheusErrorSanitized(t *testing.T) {
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A 2xx response with a Prometheus error payload; the message carries a
		// control char (escaped as JSON \u0007) and is capped to 2 KiB.
		_, _ = w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"exceeded\u0007limit"}`))
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
	})
	if !errors.Is(err, ErrPrometheusInvalid) {
		t.Fatalf("error = %v, want ErrPrometheusInvalid", err)
	}
	var perr *PrometheusError
	if !errors.As(err, &perr) {
		t.Fatalf("error = %v, want a PrometheusError", err)
	}
	if perr.ErrorType != "bad_data" {
		t.Errorf("errorType = %q, want bad_data", perr.ErrorType)
	}
	if perr.Message != "exceededlimit" {
		t.Errorf("Message = %q, want the control char stripped", perr.Message)
	}
}

func TestPrometheusTimeout(t *testing.T) {
	started := make(chan struct{})
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(successVector))
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: 30 * time.Millisecond, MaxResponseBytes: 1 << 20,
	})
	if !errors.Is(err, ErrPrometheusTimeout) {
		t.Fatalf("error = %v, want ErrPrometheusTimeout", err)
	}
	<-started
}

func TestPrometheusConcurrencyLimit(t *testing.T) {
	started := make(chan struct{})
	block := make(chan struct{})
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-block
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(successVector))
	}, 1)

	done := make(chan error, 1)
	go func() {
		_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
			Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
		})
		done <- err
	}()
	<-started

	// The first query holds the only slot: an excess query is rejected now.
	if _, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
	}); !errors.Is(err, ErrPrometheusBusy) {
		t.Fatalf("second query error = %v, want ErrPrometheusBusy", err)
	}

	close(block)
	if err := <-done; err != nil {
		t.Fatalf("first query error = %v, want nil", err)
	}
}

func TestPrometheusService(t *testing.T) {
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("unexpected proxy request")
	}, 1)
	cluster.dynamic = dynamicClientWithService(t)

	labels, err := cluster.PrometheusService(context.Background(), testDatasource())
	if err != nil {
		t.Fatalf("PrometheusService: %v", err)
	}
	if labels["app"] != "prometheus" {
		t.Errorf("labels = %v, want app=prometheus", labels)
	}

	// A port not exposed by the Service is reported as not found.
	missing := testDatasource()
	missing.Port = 8080
	if _, err := cluster.PrometheusService(context.Background(), missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing-port error = %v, want ErrNotFound", err)
	}
}

func timePtr(t time.Time) *time.Time { return &t }

// TestPrometheusFractionalSecondsSurvive verifies fractional seconds survive to
// the wire (RFC3339Nano), not silently truncated (M2).
func TestPrometheusFractionalSecondsSurvive(t *testing.T) {
	requests := make(chan prometheusRequest, 1)
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, r *http.Request) {
		requests <- prometheusRequest{path: r.URL.Path, query: r.URL.Query()}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(successVector))
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query:            "up",
		Time:             timePtr(time.Date(2026, 11, 19, 10, 0, 0, 123456789, time.UTC)),
		Timeout:          time.Second,
		MaxResponseBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("PrometheusQuery: %v", err)
	}
	req := <-requests
	if got := req.query.Get("time"); got != "2026-11-19T10:00:00.123456789Z" {
		t.Errorf("time = %q, want the fractional seconds preserved", got)
	}
}

// TestPrometheusDatasourceDNSValidation exercises the defense-in-depth DNS
// re-validation (M5).
func TestPrometheusDatasourceDNSValidation(t *testing.T) {
	if err := validatePrometheusDatasource(testDatasource()); err != nil {
		t.Fatalf("valid datasource rejected: %v", err)
	}
	cases := map[string]PrometheusDatasource{
		"bad namespace": {Namespace: "Bad NS", Service: "prometheus-k8s", Port: 9090},
		"bad service":   {Namespace: "monitoring", Service: "prometheus_k8s", Port: 9090},
		"port zero":     {Namespace: "monitoring", Service: "prometheus-k8s", Port: 0},
		"port too big":  {Namespace: "monitoring", Service: "prometheus-k8s", Port: 65536},
	}
	for name, ds := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validatePrometheusDatasource(ds); err == nil {
				t.Fatalf("validatePrometheusDatasource(%+v) error = nil, want an error", ds)
			}
		})
	}
}

// roundTripperFunc adapts a plain function to http.RoundTripper for the
// credential-plugin failure test.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestPrometheusCredentialPluginFailureClassified verifies a credential-plugin
// failure during a query is classified with a secret-free message (M3a).
func TestPrometheusCredentialPluginFailureClassified(t *testing.T) {
	logClient, err := newLogClient(&rest.Config{Host: "http://example.invalid"})
	if err != nil {
		t.Fatalf("newLogClient: %v", err)
	}
	cluster := &Cluster{
		logs:             logClient,
		credentialPlugin: "gcloud",
		promSlots:        make(chan struct{}, 1),
		promHTTP: &http.Client{
			Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New(`Get "https://example/api": exec: executable gcloud failed with exit code 1`)
			}),
		},
	}

	_, err = cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
	})
	if !errors.Is(err, ErrCredentialsUnavailable) {
		t.Fatalf("error = %v, want ErrCredentialsUnavailable", err)
	}
	var cred *CredentialError
	if !errors.As(err, &cred) || cred.Plugin != "gcloud" {
		t.Fatalf("error = %v, want CredentialError for gcloud", err)
	}
	if strings.Contains(err.Error(), "exit code") || strings.Contains(err.Error(), "exec:") {
		t.Fatalf("error = %q, must not leak plugin output", err.Error())
	}
}

// TestPrometheusErrorCapped verifies the Prometheus error message is capped to
// 2 KiB (M3f).
func TestPrometheusErrorCapped(t *testing.T) {
	long := strings.Repeat("e", 3000)
	cluster := newPrometheusTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"error","errorType":"timeout","error":"` + long + `"}`))
	}, 1)

	_, err := cluster.PrometheusQuery(context.Background(), testDatasource(), PrometheusQueryParams{
		Query: "up", Timeout: time.Second, MaxResponseBytes: 1 << 20,
	})
	var perr *PrometheusError
	if !errors.As(err, &perr) {
		t.Fatalf("error = %v, want a PrometheusError", err)
	}
	if len(perr.Message) != maxPrometheusErrorBytes {
		t.Fatalf("Message length = %d, want %d", len(perr.Message), maxPrometheusErrorBytes)
	}
}
