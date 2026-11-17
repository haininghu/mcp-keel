package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// logRequest is what a test log endpoint observed, handed over a channel so the
// test reads it without racing the handler goroutine.
type logRequest struct {
	path  string
	query url.Values
}

// newLogTestCluster starts an HTTP server running handler and returns a Cluster
// whose log client talks to it. No kubeconfig and no cluster are involved.
func newLogTestCluster(t *testing.T, handler http.HandlerFunc) *Cluster {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := newLogClient(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("newLogClient: %v", err)
	}
	return &Cluster{logs: client}
}

// writeLogStatus answers with a Kubernetes Status body, as a real API server
// does for a failed log request.
func writeLogStatus(w http.ResponseWriter, code int32, reason metav1.StatusReason) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(int(code))
	_, _ = fmt.Fprintf(w,
		`{"kind":"Status","apiVersion":"v1","status":"Failure","code":%d,"reason":%q}`,
		code, reason)
}

func TestClusterLogsRequest(t *testing.T) {
	body := []byte("first line\nsecond line\n")
	requests := make(chan logRequest, 1)
	cluster := newLogTestCluster(t, func(w http.ResponseWriter, r *http.Request) {
		requests <- logRequest{path: r.URL.Path, query: r.URL.Query()}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})

	tail, since, limit := int64(50), int64(120), int64(4096)
	got, err := cluster.Logs(context.Background(), "default", "p1", LogOptions{
		Container:    "app",
		Previous:     true,
		Timestamps:   true,
		TailLines:    &tail,
		SinceSeconds: &since,
		LimitBytes:   &limit,
	})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("Logs body = %q, want %q", got, body)
	}

	req := <-requests
	if want := "/api/v1/namespaces/default/pods/p1/log"; req.path != want {
		t.Fatalf("request path = %q, want %q", req.path, want)
	}
	wantQuery := map[string]string{
		"container":    "app",
		"previous":     "true",
		"timestamps":   "true",
		"tailLines":    "50",
		"sinceSeconds": "120",
		"limitBytes":   "4096",
	}
	for key, want := range wantQuery {
		if got := req.query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}
	if req.query.Has("follow") {
		t.Errorf("query follow = %q, want it omitted", req.query.Get("follow"))
	}
}

func TestClusterLogsDefaults(t *testing.T) {
	requests := make(chan logRequest, 1)
	cluster := newLogTestCluster(t, func(w http.ResponseWriter, r *http.Request) {
		requests <- logRequest{path: r.URL.Path, query: r.URL.Query()}
		w.Header().Set("Content-Type", "text/plain")
	})

	if _, err := cluster.Logs(context.Background(), "default", "p1", LogOptions{}); err != nil {
		t.Fatalf("Logs: %v", err)
	}
	req := <-requests
	if len(req.query) != 0 {
		t.Fatalf("query = %v, want no parameters for zero options", req.query)
	}
}

func TestClusterLogsRejectsEmptyArguments(t *testing.T) {
	cluster := newLogTestCluster(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request for path %q", r.URL.Path)
	})
	ctx := context.Background()

	cases := []struct {
		name      string
		namespace string
		pod       string
	}{
		{name: "empty namespace", namespace: "", pod: "p1"},
		{name: "empty pod", namespace: "default", pod: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cluster.Logs(ctx, tc.namespace, tc.pod, LogOptions{}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestClusterLogsErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		code       int32
		reason     metav1.StatusReason
		want       error
		wantStatus int
	}{
		{name: "not found", code: http.StatusNotFound, reason: metav1.StatusReasonNotFound, want: ErrNotFound},
		{name: "forbidden", code: http.StatusForbidden, reason: metav1.StatusReasonForbidden, want: ErrForbidden, wantStatus: http.StatusForbidden},
		{name: "unauthorized", code: http.StatusUnauthorized, reason: metav1.StatusReasonUnauthorized, want: ErrUnauthorized, wantStatus: http.StatusUnauthorized},
		{name: "server error", code: http.StatusInternalServerError, reason: metav1.StatusReasonInternalError, want: ErrRequestFailed, wantStatus: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newLogTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
				writeLogStatus(w, tc.code, tc.reason)
			})

			_, err := cluster.Logs(context.Background(), "default", "p1", LogOptions{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Logs error = %v, want %v", err, tc.want)
			}
			if got := HTTPStatus(err); got != tc.wantStatus {
				t.Fatalf("HTTPStatus = %d, want %d", got, tc.wantStatus)
			}
		})
	}
}

func TestClusterLogsReadCap(t *testing.T) {
	body := bytes.Repeat([]byte("log line\n"), 1000)
	limit := int64(64)
	cluster := newLogTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	})

	got, err := cluster.Logs(context.Background(), "default", "p1", LogOptions{LimitBytes: &limit})
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if int64(len(got)) != limit {
		t.Fatalf("Logs returned %d bytes, want %d", len(got), limit)
	}
	if !bytes.Equal(got, body[:limit]) {
		t.Fatalf("Logs body = %q, want the first %d bytes of the stream", got, limit)
	}
}

func TestClusterLogsReadErrorMapped(t *testing.T) {
	// A handler that closes the connection mid-body makes the read fail; the
	// error must be mapped to a sentinel instead of surfacing raw I/O text.
	cluster := newLogTestCluster(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "100")
		_, _ = fmt.Fprint(w, "partial")
	})

	_, err := cluster.Logs(context.Background(), "default", "p1", LogOptions{})
	if !errors.Is(err, ErrRequestFailed) {
		t.Fatalf("Logs error = %v, want ErrRequestFailed", err)
	}
}
