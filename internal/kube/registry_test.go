package kube

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hvo/mcp-keel/internal/config"
)

const kubeconfigYAML = `apiVersion: v1
kind: Config
clusters:
- name: c1
  cluster:
    server: https://example.invalid
contexts:
- name: prod-ctx
  context:
    cluster: c1
    user: u1
- name: dev-ctx
  context:
    cluster: c1
    user: u1
current-context: prod-ctx
users:
- name: u1
  user:
    token: super-secret-token
`

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kubeconfigYAML), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func testConfig(kubeconfig string, contexts []string) *config.Config {
	return &config.Config{
		Version: 1,
		Server: config.ServerConfig{
			Name:              "mcp-keel",
			LogLevel:          config.LogLevelInfo,
			RequestTimeout:    config.Duration(30 * time.Second),
			DiscoveryTimeout:  config.Duration(10 * time.Second),
			DiscoveryCacheTTL: config.Duration(10 * time.Minute),
			QPS:               20,
			Burst:             50,
			Kubeconfig:        kubeconfig,
		},
		Providers: []config.ProviderConfig{
			{Name: "prod", Contexts: contexts},
		},
	}
}

func TestNewRegistryLiteralContext(t *testing.T) {
	path := writeKubeconfig(t)
	registry, err := NewRegistry(testConfig(path, []string{"prod-ctx"}), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	cluster, err := registry.Cluster("prod", "prod-ctx")
	if err != nil {
		t.Fatalf("Cluster: %v", err)
	}
	if cluster.Provider() != "prod" || cluster.Context() != "prod-ctx" {
		t.Fatalf("cluster = %s/%s", cluster.Provider(), cluster.Context())
	}
	// The same cluster is cached.
	again, err := registry.Cluster("prod", "prod-ctx")
	if err != nil || again != cluster {
		t.Fatalf("Cluster not cached: %v, %v", again, err)
	}
}

func TestNewRegistryMissingLiteralContext(t *testing.T) {
	path := writeKubeconfig(t)
	if _, err := NewRegistry(testConfig(path, []string{"missing-ctx"}), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("expected error for a literal context absent from the kubeconfig")
	}
}

func TestNewRegistryGlobWithoutMatchWarns(t *testing.T) {
	path := writeKubeconfig(t)
	handler := &recordingHandler{}
	registry, err := NewRegistry(testConfig(path, []string{"staging-*"}), slog.New(handler))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if registry == nil {
		t.Fatal("registry is nil")
	}
	if !handler.hasWarn() {
		t.Fatal("expected a warning for a context glob with zero matches")
	}
}

func TestNewRegistryGlobMatches(t *testing.T) {
	path := writeKubeconfig(t)
	handler := &recordingHandler{}
	registry, err := NewRegistry(testConfig(path, []string{"*-ctx"}), slog.New(handler))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if handler.hasWarn() {
		t.Fatal("did not expect a warning for a matching glob")
	}
	cluster, err := registry.Cluster("prod", "dev-ctx")
	if err != nil {
		t.Fatalf("Cluster: %v", err)
	}
	if cluster.Context() != "dev-ctx" {
		t.Fatalf("context = %s", cluster.Context())
	}
}

func TestRegistryUnknownProvider(t *testing.T) {
	path := writeKubeconfig(t)
	registry, err := NewRegistry(testConfig(path, []string{"prod-ctx"}), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := registry.Cluster("nope", "prod-ctx"); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("error = %v, want unknown provider", err)
	}
}

func TestRegistryContextOutsideProvider(t *testing.T) {
	path := writeKubeconfig(t)
	registry, err := NewRegistry(testConfig(path, []string{"prod-ctx"}), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, err := registry.Cluster("prod", "dev-ctx"); !errors.Is(err, ErrUnknownContext) {
		t.Fatalf("error = %v, want unknown context", err)
	}
}

func TestNewRegistryNilConfig(t *testing.T) {
	if _, err := NewRegistry(nil, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("expected error for nil config")
	}
}

// recordingHandler captures log records for assertions.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, record)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

func (h *recordingHandler) hasWarn() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, record := range h.records {
		if record.Level >= slog.LevelWarn {
			return true
		}
	}
	return false
}

func TestRegistryContexts(t *testing.T) {
	path := writeKubeconfig(t)
	registry, err := NewRegistry(testConfig(path, []string{"prod-*", "dev-ctx", "staging-*"}), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	got, err := registry.Contexts("prod")
	if err != nil {
		t.Fatalf("Contexts: %v", err)
	}
	want := []string{"dev-ctx", "prod-ctx"}
	if !slices.Equal(got, want) {
		t.Fatalf("Contexts = %v, want %v", got, want)
	}

	if _, err := registry.Contexts("nope"); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("Contexts(unknown) error = %v, want ErrUnknownProvider", err)
	}

	// An unreadable kubeconfig is reported as an error and never returns names.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove kubeconfig: %v", err)
	}
	if _, err := registry.Contexts("prod"); err == nil {
		t.Fatal("expected an error for an unreadable kubeconfig")
	}
}
