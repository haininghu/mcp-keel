//go:build e2e

// Package e2e contains end-to-end smoke tests for mcp-keel. They exercise the
// full stack (config -> kube/client-go -> policy -> server -> MCP) against a
// real Kubernetes API server started by envtest, and the built binary over
// stdio.
//
// The tests are gated behind the "e2e" build tag so the default "go test ./..."
// stays fast. Run them with:
//
//	KUBEBUILDER_ASSETS="$(setup-envtest use -p path)" go test -tags=e2e -count=1 ./e2e/...
//
// If the envtest assets cannot be found the tests skip instead of failing.
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/hvo/mcp-keel/internal/config"
	"github.com/hvo/mcp-keel/internal/kube"
	"github.com/hvo/mcp-keel/internal/server"
)

// provider names used by the generated configuration.
const (
	mainProvider    = "main"
	inspectProvider = "inspect"
	contextName     = "e2e"
)

// environment holds everything the tests share: the envtest control plane, the
// generated kubeconfig and config, the in-process MCP session and the path to
// the built binary.
type environment struct {
	restConfig *rest.Config
	dynamic    dynamic.Interface

	kubeconfigPath string
	configPath     string
	binPath        string

	logs    *bytes.Buffer
	session *mcp.ClientSession

	testEnv *envtest.Environment
	workDir string
}

var (
	sharedEnv *environment
	setupSkip string
)

// TestMain starts envtest once and tears it down after all tests. When the
// envtest assets are missing it records a skip reason so every test skips with
// a clear message instead of failing.
func TestMain(m *testing.M) {
	assetsDir, ok := resolveAssetsDir()
	if !ok {
		setupSkip = "envtest assets not found; run " +
			"`setup-envtest use -p path` and export KUBEBUILDER_ASSETS, then retry"
		os.Exit(m.Run())
	}

	env, err := startEnvironment(assetsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: setup failed:", err)
		os.Exit(1)
	}
	sharedEnv = env

	code := m.Run()
	env.stop()
	os.Exit(code)
}

// requireEnv returns the shared environment or skips the test when setup could
// not run.
func requireEnv(t *testing.T) *environment {
	t.Helper()
	if sharedEnv == nil {
		t.Skip(setupSkip)
	}
	return sharedEnv
}

// resolveAssetsDir locates the envtest binaries. KUBEBUILDER_ASSETS wins, then
// the setup-envtest default location is searched for a matching k8s directory.
func resolveAssetsDir() (string, bool) {
	if dir := os.Getenv("KUBEBUILDER_ASSETS"); dir != "" {
		if isDir(dir) {
			return dir, true
		}
	}
	base, err := envtest.SetupEnvtestDefaultBinaryAssetsDirectory()
	if err != nil {
		return "", false
	}
	pattern := filepath.Join(base, "k8s", "*-"+runtime.GOOS+"-"+runtime.GOARCH)
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		return "", false
	}
	// Glob returns sorted matches; prefer the highest version.
	return matches[len(matches)-1], true
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// startEnvironment boots envtest, writes the fixtures, config and kubeconfig,
// builds the binary and connects an in-process MCP session.
func startEnvironment(assetsDir string) (*environment, error) {
	workDir, err := os.MkdirTemp("", "mcp-keel-e2e-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	env := &environment{workDir: workDir}

	testEnv := &envtest.Environment{
		BinaryAssetsDirectory:    assetsDir,
		ControlPlaneStartTimeout: 90 * time.Second,
		ControlPlaneStopTimeout:  60 * time.Second,
	}
	env.testEnv = testEnv

	restConfig, err := testEnv.Start()
	if err != nil {
		env.cleanup()
		return nil, fmt.Errorf("start envtest: %w", err)
	}
	env.restConfig = restConfig

	if env.kubeconfigPath, err = writeKubeconfig(workDir, restConfig); err != nil {
		env.cleanup()
		return nil, err
	}
	if env.dynamic, err = dynamic.NewForConfig(restConfig); err != nil {
		env.cleanup()
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	if err := env.createFixtures(); err != nil {
		env.cleanup()
		return nil, err
	}
	if env.configPath, err = writeConfig(workDir, env.kubeconfigPath); err != nil {
		env.cleanup()
		return nil, err
	}
	if err := env.connectInProcess(); err != nil {
		env.cleanup()
		return nil, err
	}
	if env.binPath, err = buildBinary(workDir); err != nil {
		env.cleanup()
		return nil, err
	}
	return env, nil
}

// stop releases the in-process session and the control plane.
func (e *environment) stop() {
	if e.session != nil {
		_ = e.session.Close()
	}
	e.cleanup()
}

// cleanup tears down the control plane and removes the working directory.
func (e *environment) cleanup() {
	if e.testEnv != nil {
		_ = e.testEnv.Stop()
		e.testEnv = nil
	}
	if e.workDir != "" {
		_ = os.RemoveAll(e.workDir)
		e.workDir = ""
	}
}

// connectInProcess wires config -> kube registry -> server -> MCP client over an
// in-memory transport.
func (e *environment) connectInProcess() error {
	cfg, err := config.Load(e.configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	e.logs = &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	registry, err := kube.NewRegistry(cfg, logger)
	if err != nil {
		return fmt.Errorf("kube registry: %w", err)
	}
	srv := server.New(cfg, server.KubeRegistry(registry), logger)

	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := srv.MCPServer("e2e").Connect(ctx, serverTransport, nil); err != nil {
		return fmt.Errorf("server connect: %w", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "v0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		return fmt.Errorf("client connect: %w", err)
	}
	e.session = session
	return nil
}

// writeKubeconfig reverse-engineers a kubeconfig with a single "e2e" context
// from an envtest rest.Config.
func writeKubeconfig(dir string, restConfig *rest.Config) (string, error) {
	protocol := "https"
	if !rest.IsConfigTransportTLS(*restConfig) {
		protocol = "http"
	}
	baseURL, err := url.Parse(restConfig.Host)
	if err != nil {
		return "", fmt.Errorf("parse host: %w", err)
	}

	apiConfig := clientcmdapi.NewConfig()
	apiConfig.Clusters[contextName] = &clientcmdapi.Cluster{
		Server:                   (&url.URL{Scheme: protocol, Host: baseURL.Host, Path: restConfig.APIPath}).String(),
		CertificateAuthorityData: restConfig.CAData,
		InsecureSkipTLSVerify:    restConfig.Insecure,
	}
	apiConfig.AuthInfos[contextName] = &clientcmdapi.AuthInfo{
		ClientCertificateData: restConfig.CertData,
		ClientKeyData:         restConfig.KeyData,
		Token:                 restConfig.BearerToken,
		Username:              restConfig.Username,
		Password:              restConfig.Password,
	}
	kubeContext := clientcmdapi.NewContext()
	kubeContext.Cluster = contextName
	kubeContext.AuthInfo = contextName
	kubeContext.Namespace = "default"
	apiConfig.Contexts[contextName] = kubeContext
	apiConfig.CurrentContext = contextName

	data, err := clientcmd.Write(*apiConfig)
	if err != nil {
		return "", fmt.Errorf("serialize kubeconfig: %w", err)
	}
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write kubeconfig: %w", err)
	}
	return path, nil
}

// configTemplate is the mcp-keel configuration exercised by the tests. The
// rules deliberately cover: a namespace deny, a label-based deny (noai), broad
// pod/deployment allows, an allow wildcard that must not reach secrets, and a
// cluster-scoped rule using the "" marker. A second provider opts in to the
// introspection tools only.
const configTemplate = `version: 1

server:
  name: mcp-keel-e2e
  log_level: error
  kubeconfig: %q
  max_list_items: 10
  discovery_cache_ttl: 0s

providers:
  - name: main
    contexts: ["e2e"]
    rules:
      # Deny everything in the "blocked" namespace.
      - namespaces: ["blocked"]
        effect: deny

      # Deny every operation on objects carrying the "noai" label.
      - namespaces: ["*"]
        effect: deny
        capabilities:
          - "*:*":
              labels:
                require: ["noai"]

      # Read pods, deployments and (via the allow wildcard) everything else that
      # is neither sensitive nor a subresource. The wildcard must NOT reach
      # secrets, so "secrets:get" is intentionally absent.
      - namespaces: ["*"]
        effect: allow
        capabilities:
          - core/pods:get
          - core/pods:list
          - apps/deployments:get
          - apps/deployments:list
          - "*:get"
          - "*:list"

      # Cluster-scoped resources use the "" marker.
      - namespaces: [""]
        effect: allow
        capabilities:
          - core/namespaces:get
          - core/namespaces:list

  - name: inspect
    contexts: ["e2e"]
    policy_read: true
    rules: []
`

// writeConfig renders the test configuration referencing the temp kubeconfig.
func writeConfig(dir, kubeconfigPath string) (string, error) {
	path := filepath.Join(dir, "mcp-keel.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(configTemplate, kubeconfigPath)), 0o600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	return path, nil
}

// buildBinary compiles cmd/mcp-keel into the working directory.
func buildBinary(dir string) (string, error) {
	binPath := filepath.Join(dir, "mcp-keel")
	cmd := exec.Command("go", "build", "-o", binPath, "github.com/hvo/mcp-keel/cmd/mcp-keel")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, output)
	}
	return binPath, nil
}

// --- fixtures ------------------------------------------------------------

// createFixtures creates the namespaces, pods, deployment and secret the
// scenarios rely on.
func (e *environment) createFixtures() error {
	ctx := context.Background()

	for _, namespace := range []string{"allowed", "blocked", "labeled"} {
		if err := e.createObject(ctx, namespaceGVR, "", namespaceResource(namespace)); err != nil {
			return err
		}
	}

	pods := []struct {
		namespace string
		name      string
		labels    map[string]any
	}{
		{namespace: "allowed", name: "web-1", labels: map[string]any{"app": "web"}},
		{namespace: "allowed", name: "web-2", labels: map[string]any{"app": "web"}},
		{namespace: "allowed", name: "db-1", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-2", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-3", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-4", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-5", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-6", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-7", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-8", labels: map[string]any{"app": "db"}},
		{namespace: "allowed", name: "db-9", labels: map[string]any{"app": "db"}},
		{namespace: "labeled", name: "noai-pod", labels: map[string]any{"noai": "true"}},
		{namespace: "blocked", name: "blocked-pod", labels: map[string]any{"app": "web"}},
	}
	for _, pod := range pods {
		if err := e.createObject(ctx, podsGVR, pod.namespace, podResource(pod.name, pod.labels)); err != nil {
			return err
		}
	}

	if err := e.createObject(ctx, deploymentsGVR, "allowed", deploymentResource("web-deploy")); err != nil {
		return err
	}
	if err := e.createObject(ctx, secretsGVR, "allowed", secretResource("creds")); err != nil {
		return err
	}
	return nil
}

func (e *environment) createObject(ctx context.Context, gvr schema.GroupVersionResource, namespace string, obj *unstructured.Unstructured) error {
	resource := e.dynamic.Resource(gvr)
	// FieldManager makes the API server record managedFields, which the server
	// must strip from its responses.
	options := metav1.CreateOptions{FieldManager: "mcp-keel-e2e"}
	var err error
	if namespace != "" {
		_, err = resource.Namespace(namespace).Create(ctx, obj, options)
	} else {
		_, err = resource.Create(ctx, obj, options)
	}
	if err != nil {
		return fmt.Errorf("create %s %s/%s: %w", obj.GetKind(), namespace, obj.GetName(), err)
	}
	return nil
}

// --- test helpers --------------------------------------------------------

func (e *environment) call(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := e.session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	return res
}

func (e *environment) callOK(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	res := e.call(t, name, args)
	if res.IsError {
		t.Fatalf("%s returned an error: %s", name, resultText(t, res))
	}
	return decodeJSON(t, resultText(t, res))
}

func (e *environment) callNotFound(t *testing.T, name string, args map[string]any) {
	t.Helper()
	res := e.call(t, name, args)
	if !res.IsError {
		t.Fatalf("%s = %s, want a not-found error", name, resultText(t, res))
	}
	if text := resultText(t, res); !strings.Contains(text, "not found") {
		t.Fatalf("%s error = %q, want it to contain %q", name, text, "not found")
	}
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

// metadataOf returns the metadata map of an unstructured item decoded from JSON.
func metadataOf(t *testing.T, item any) map[string]any {
	t.Helper()
	obj, ok := item.(map[string]any)
	if !ok {
		t.Fatalf("item type = %T, want map[string]any", item)
	}
	meta, ok := obj["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("item metadata type = %T, want map[string]any", obj["metadata"])
	}
	return meta
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()
	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("value type = %T, want []any", value)
	}
	out := make([]string, len(raw))
	for i, entry := range raw {
		s, ok := entry.(string)
		if !ok {
			t.Fatalf("entry type = %T, want string", entry)
		}
		out[i] = s
	}
	return out
}

// --- scenarios -----------------------------------------------------------

// TestEndToEnd drives the in-process server through the MCP client.
func TestEndToEnd(t *testing.T) {
	env := requireEnv(t)

	t.Run("get_allowed_pod", func(t *testing.T) {
		out := env.callOK(t, "get", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/pods", "namespace": "allowed", "name": "web-1",
		})
		if got := out["resource"]; got != "pods" {
			t.Fatalf("resource = %v, want canonical %q", got, "pods")
		}
		if got := out["namespace"]; got != "allowed" {
			t.Fatalf("namespace = %v, want %q", got, "allowed")
		}
		meta := metadataOf(t, out["object"])
		if got := meta["name"]; got != "web-1" {
			t.Fatalf("object name = %v, want %q", got, "web-1")
		}
		if _, present := meta["managedFields"]; present {
			t.Fatalf("managedFields was not stripped from the response")
		}
	})

	t.Run("get_denied_namespace", func(t *testing.T) {
		env.callNotFound(t, "get", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/pods", "namespace": "blocked", "name": "blocked-pod",
		})
	})

	t.Run("get_label_excluded", func(t *testing.T) {
		env.callNotFound(t, "get", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/pods", "namespace": "labeled", "name": "noai-pod",
		})
	})

	t.Run("get_deployment", func(t *testing.T) {
		out := env.callOK(t, "get", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "apps/deployments", "namespace": "allowed", "name": "web-deploy",
		})
		if got := out["resource"]; got != "apps/deployments" {
			t.Fatalf("resource = %v, want %q", got, "apps/deployments")
		}
	})

	t.Run("list_pods_with_label_filter", func(t *testing.T) {
		out := env.callOK(t, "list", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/pods", "namespace": "allowed", "labelSelector": "app=web",
		})
		items, ok := out["items"].([]any)
		if !ok {
			t.Fatalf("items type = %T, want []any", out["items"])
		}
		if len(items) != 2 {
			t.Fatalf("got %d items, want 2", len(items))
		}
		for _, item := range items {
			meta := metadataOf(t, item)
			labels, _ := meta["labels"].(map[string]any)
			if labels["app"] != "web" {
				t.Fatalf("item %v has app=%v, want web", meta["name"], labels["app"])
			}
		}
		if _, present := out["truncated"]; !present {
			t.Fatalf("list response is missing the truncated field")
		}
	})

	t.Run("get_secret_denied_by_sensitive_set", func(t *testing.T) {
		// Only the allow wildcard "*:get" could reach secrets, and it never
		// does. "secrets:get" is deliberately not configured.
		env.callNotFound(t, "get", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/secrets", "namespace": "allowed", "name": "creds",
		})
	})

	t.Run("list_cluster_scoped_namespaces", func(t *testing.T) {
		out := env.callOK(t, "list", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/namespaces",
		})
		if got := out["resource"]; got != "namespaces" {
			t.Fatalf("resource = %v, want %q", got, "namespaces")
		}
		items, ok := out["items"].([]any)
		if !ok {
			t.Fatalf("items type = %T, want []any", out["items"])
		}
		found := make(map[string]bool, len(items))
		for _, item := range items {
			found[metadataOf(t, item)["name"].(string)] = true
		}
		for _, want := range []string{"allowed", "blocked", "labeled"} {
			if !found[want] {
				t.Fatalf("namespaces list is missing %q (got %v)", want, found)
			}
		}
	})

	t.Run("introspection_only_policy_read_providers", func(t *testing.T) {
		rules := env.callOK(t, "list_configured_rules", map[string]any{})
		if names := providerNames(t, rules); len(names) != 1 || names[0] != inspectProvider {
			t.Fatalf("list_configured_rules providers = %v, want [%s]", names, inspectProvider)
		}

		clusters := env.callOK(t, "list_clusters", map[string]any{})
		if names := providerNames(t, clusters); len(names) != 1 || names[0] != inspectProvider {
			t.Fatalf("list_clusters providers = %v, want [%s]", names, inspectProvider)
		}
		providers, _ := clusters["providers"].([]any)
		entry, _ := providers[0].(map[string]any)
		contexts := stringSlice(t, entry["contexts"])
		if len(contexts) != 1 || contexts[0] != contextName {
			t.Fatalf("inspect contexts = %v, want [%s]", contexts, contextName)
		}
	})

	t.Run("list_limit_clamped", func(t *testing.T) {
		// max_list_items is 10; the namespace holds eleven allowed pods.
		out := env.callOK(t, "list", map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/pods", "namespace": "allowed", "limit": 100,
		})
		items, ok := out["items"].([]any)
		if !ok {
			t.Fatalf("items type = %T, want []any", out["items"])
		}
		if len(items) != 10 {
			t.Fatalf("got %d items, want the clamped limit 10", len(items))
		}
		if truncated, _ := out["truncated"].(bool); !truncated {
			t.Fatalf("truncated = false, want true for a clamped list")
		}
	})
}

func providerNames(t *testing.T, out map[string]any) []string {
	t.Helper()
	providers, ok := out["providers"].([]any)
	if !ok {
		t.Fatalf("providers type = %T, want []any", out["providers"])
	}
	names := make([]string, 0, len(providers))
	for _, provider := range providers {
		entry, ok := provider.(map[string]any)
		if !ok {
			t.Fatalf("provider type = %T, want map[string]any", provider)
		}
		name, _ := entry["provider"].(string)
		names = append(names, name)
	}
	return names
}

// TestBinaryOverStdio builds the real binary, launches it with the generated
// config and speaks MCP over its stdin/stdout pipes. It verifies initialize,
// tools/list and one successful tools/call. The SDK has no dedicated
// subprocess transport, so mcp.IOTransport is wired to the process pipes.
func TestBinaryOverStdio(t *testing.T) {
	env := requireEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, env.binPath, "-config", env.configPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start binary: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	transport := &mcp.IOTransport{Reader: stdout, Writer: stdin}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-binary-client", Version: "v0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to binary: %v\nstderr:\n%s", err, stderr.String())
	}
	t.Cleanup(func() { _ = session.Close() })

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		got[tool.Name] = true
	}
	for _, want := range []string{"get", "list", "list_configured_rules", "list_clusters"} {
		if !got[want] {
			t.Fatalf("tools/list is missing %q (got %v)", want, got)
		}
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get",
		Arguments: map[string]any{
			"provider": mainProvider, "context": contextName,
			"resource": "core/pods", "namespace": "allowed", "name": "web-1",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(get): %v\nstderr:\n%s", err, stderr.String())
	}
	if res.IsError {
		t.Fatalf("CallTool(get) returned an error: %s", resultText(t, res))
	}
	out := decodeJSON(t, resultText(t, res))
	if got := out["resource"]; got != "pods" {
		t.Fatalf("resource = %v, want %q", got, "pods")
	}
}

// --- resource constructors ----------------------------------------------

var (
	namespaceGVR   = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	podsGVR        = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	secretsGVR     = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	deploymentsGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
)

func namespaceResource(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   map[string]any{"name": name},
	}}
}

func podResource(name string, labels map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":   name,
			"labels": labels,
		},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"name": "app", "image": "registry.k8s.io/pause:3.9"},
			},
		},
	}}
}

func deploymentResource(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":   name,
			"labels": map[string]any{"app": "web"},
		},
		"spec": map[string]any{
			"replicas": int64(1),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "web"}},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "web", "image": "registry.k8s.io/pause:3.9"},
					},
				},
			},
		},
	}}
}

func secretResource(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata":   map[string]any{"name": name},
		"type":       "Opaque",
		"data": map[string]any{
			"password": base64.StdEncoding.EncodeToString([]byte("s3cr3t")),
		},
	}}
}
