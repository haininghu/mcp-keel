// Package server exposes the mcp-keel read-only Kubernetes tools over MCP. It
// wires the configuration, the policy engine and the kube backend into four
// tools (get, list, list_configured_rules, list_clusters). Every
// capability-gated tool canonicalises the resource, authorizes the request and
// only then touches the cluster; denied, filter-excluded and marker-protected
// objects are reported exactly like non-existent ones (ADR 0008, ADR 0013).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
)

// errNotFound is the single, existence-hiding failure returned for a denied or
// absent object (ADR 0008). A denied get is indistinguishable from a missing
// one and a denied list is an empty result.
var errNotFound = errors.New("not found")

// errAuthorizationFailed is returned when the policy for a provider/context
// cannot be built. It fails closed and reveals no configuration details.
var errAuthorizationFailed = errors.New("authorization failed")

// Cluster abstracts the per-(provider, context) Kubernetes client the tools
// use. It mirrors the exported surface of *kube.Cluster; the interface lets the
// tool tests run without a cluster.
type Cluster interface {
	// Canonicalize resolves a raw resource identifier to its canonical form
	// (ADR 0012). The bool reports a standalone "*" wildcard.
	Canonicalize(ctx context.Context, raw string) (policy.Resource, bool, error)
	// CanonicalizeAll is the ambiguity-tolerant variant used to extend the
	// sensitive-resource set: it returns every canonical form a name matches
	// (ADR 0004).
	CanonicalizeAll(ctx context.Context, raw string) ([]policy.Resource, error)
	// SupportsVerb reports whether the resource supports the verb.
	SupportsVerb(ctx context.Context, res policy.Resource, verb policy.Verb) (bool, error)
	// Namespaced reports whether the resource is namespaced, from discovery.
	Namespaced(ctx context.Context, res policy.Resource) (bool, error)
	// Get fetches a single object.
	Get(ctx context.Context, res policy.Resource, namespace, name string) (*unstructured.Unstructured, error)
	// List fetches a bounded window of objects.
	List(ctx context.Context, res policy.Resource, namespace, labelSelector string, limit int) ([]unstructured.Unstructured, error)
	// NamespaceMarked reports whether the namespace carries the marker label.
	NamespaceMarked(ctx context.Context, namespace, label string) (bool, error)
}

// ClusterRegistry resolves a (provider, context) pair to a cluster client.
type ClusterRegistry interface {
	// Cluster returns the cluster for provider and context, or an error that
	// wraps kube.ErrUnknownProvider or kube.ErrUnknownContext.
	Cluster(provider, context string) (Cluster, error)
	// Contexts returns the concrete kubeconfig context names of a provider that
	// match its configured context globs, sorted. It exposes only names.
	Contexts(provider string) ([]string, error)
}

// kubeRegistry adapts a *kube.Registry to ClusterRegistry.
type kubeRegistry struct{ registry *kube.Registry }

// KubeRegistry adapts a real kube registry to the ClusterRegistry interface.
func KubeRegistry(registry *kube.Registry) ClusterRegistry {
	return kubeRegistry{registry: registry}
}

// Cluster returns the cached cluster for provider and context.
func (k kubeRegistry) Cluster(provider, contextName string) (Cluster, error) {
	cluster, err := k.registry.Cluster(provider, contextName)
	if err != nil {
		return nil, err
	}
	return cluster, nil
}

// Contexts returns the provider's concrete kubeconfig context names.
func (k kubeRegistry) Contexts(provider string) ([]string, error) {
	return k.registry.Contexts(provider)
}

// policyKey identifies a compiled policy. Policies are canonicalised per
// (provider, context) because discovery differs between contexts.
type policyKey struct {
	provider string
	context  string
}

// Server holds the MCP tool handlers and their dependencies. It is safe for
// concurrent use.
type Server struct {
	cfg       *config.Config
	registry  ClusterRegistry
	logger    *slog.Logger
	providers map[string]*config.ProviderConfig

	policyMu    sync.Mutex
	policyByKey map[policyKey]*policy.Policy
}

// New constructs a Server. A nil logger discards all log output. The returned
// Server keeps cfg and registry by reference.
func New(cfg *config.Config, registry ClusterRegistry, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	providers := make(map[string]*config.ProviderConfig, len(cfg.Providers))
	for i := range cfg.Providers {
		providers[cfg.Providers[i].Name] = &cfg.Providers[i]
	}
	return &Server{
		cfg:         cfg,
		registry:    registry,
		logger:      logger,
		providers:   providers,
		policyByKey: make(map[policyKey]*policy.Policy),
	}
}

// MCPServer builds an mcp.Server with all four tools registered. version is
// advertised to clients and is typically injected at build time.
func (s *Server) MCPServer(version string) *mcp.Server {
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: s.cfg.Server.Name, Version: version}, nil)

	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name:        "get",
		Description: "Fetch a single Kubernetes object by name, under policy. Requires the resource:get capability; denied or non-existent objects are reported identically as not found.",
	}, s.handleGet)

	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name:        "list",
		Description: "List Kubernetes objects, under policy, with per-item authorization. Requires the resource:list capability; items the caller may not see are omitted.",
	}, s.handleList)

	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name:        "list_configured_rules",
		Description: "List the configured access rules for providers that opt in with policy_read: true. Reports configuration only, never effective access or live object state. Other providers are omitted.",
	}, s.handleListConfiguredRules)

	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name:        "list_clusters",
		Description: "List the providers and their configured context patterns that opt in with policy_read: true, so an agent can form valid requests. Other providers are omitted.",
	}, s.handleListClusters)

	return mcpSrv
}

// getInput is the argument object of the get tool.
type getInput struct {
	Provider  string `json:"provider" jsonschema:"logical provider name"`
	Context   string `json:"context" jsonschema:"kubeconfig context; must match the provider's contexts"`
	Resource  string `json:"resource" jsonschema:"resource identifier: group/resource[/subresource] or an alias"`
	Namespace string `json:"namespace,omitempty" jsonschema:"namespace; required for a namespaced resource, omitted for a cluster-scoped one"`
	Name      string `json:"name" jsonschema:"object name"`
}

// listInput is the argument object of the list tool.
type listInput struct {
	Provider      string `json:"provider" jsonschema:"logical provider name"`
	Context       string `json:"context" jsonschema:"kubeconfig context; must match the provider's contexts"`
	Resource      string `json:"resource" jsonschema:"resource identifier: group/resource[/subresource] or an alias"`
	Namespace     string `json:"namespace,omitempty" jsonschema:"namespace; omitted means all namespaces for a namespaced resource and is rejected for a cluster-scoped one"`
	LabelSelector string `json:"labelSelector,omitempty" jsonschema:"optional label selector passed to the API server; it never replaces the policy label check"`
	Limit         int    `json:"limit,omitempty" jsonschema:"optional maximum number of items; clamped to the configured server limit"`
}

// resolveRegistry resolves and validates a provider/context pair, mapping the
// kube sentinels to safe messages. It never returns kubeconfig details.
func (s *Server) resolveRegistry(provider, contextName string) (Cluster, error) {
	if err := validateText("provider", provider, maxIdentifierBytes); err != nil {
		return nil, err
	}
	if err := validateText("context", contextName, maxIdentifierBytes); err != nil {
		return nil, err
	}
	cluster, err := s.registry.Cluster(provider, contextName)
	if err != nil {
		switch {
		case errors.Is(err, kube.ErrUnknownProvider):
			return nil, fmt.Errorf("unknown provider %q", provider)
		case errors.Is(err, kube.ErrUnknownContext):
			return nil, fmt.Errorf("unknown context %q for provider %q", contextName, provider)
		default:
			// The raw error can carry kubeconfig paths or exec-plugin output,
			// so it is never logged (ADR 0007); the provider/context identify
			// the failure for the operator.
			s.logger.Error("resolving cluster failed",
				"provider", provider, "context", contextName)
			return nil, errors.New("could not resolve the requested provider and context")
		}
	}
	return cluster, nil
}

// canonicalizeResolve canonicalises a tool resource argument and rejects the
// standalone wildcard, which is never a valid object identifier.
func canonicalizeResolve(ctx context.Context, cluster Cluster, raw string) (policy.Resource, error) {
	if err := validateText("resource", raw, maxIdentifierBytes); err != nil {
		return policy.Resource{}, err
	}
	res, wildcard, err := cluster.Canonicalize(ctx, raw)
	if err != nil {
		return policy.Resource{}, resourceError(raw, err)
	}
	if wildcard || res.Name == "" {
		return policy.Resource{}, fmt.Errorf("unknown resource: %s", raw)
	}
	return res, nil
}

// resourceError maps a canonicalisation failure to the resource-shape error of
// the method specs. It never leaks the discovery error body.
func resourceError(raw string, err error) error {
	switch {
	case errors.Is(err, kube.ErrAmbiguousResource):
		return fmt.Errorf("ambiguous resource: %s", raw)
	case errors.Is(err, kube.ErrUnknownResource),
		errors.Is(err, kube.ErrInvalidResource),
		errors.Is(err, kube.ErrPartialDiscovery):
		return fmt.Errorf("unknown resource: %s", raw)
	default:
		return fmt.Errorf("could not resolve resource: %s", raw)
	}
}

// resourceInspectionError maps a discovery failure during namespaced/verb
// inspection. An unresolved resource stays "unknown resource".
func resourceInspectionError(raw string, err error) error {
	switch {
	case errors.Is(err, kube.ErrAmbiguousResource):
		return fmt.Errorf("ambiguous resource: %s", raw)
	case errors.Is(err, kube.ErrUnknownResource),
		errors.Is(err, kube.ErrInvalidResource),
		errors.Is(err, kube.ErrPartialDiscovery):
		return fmt.Errorf("unknown resource: %s", raw)
	default:
		return errors.New("could not resolve the resource in the cluster")
	}
}

// mapKubeError maps a cluster API sentinel to a safe message and appends the
// HTTP status when the kube layer preserved one (ADR 0008).
func mapKubeError(err error) error {
	switch {
	case errors.Is(err, kube.ErrNotFound):
		return errNotFound
	case errors.Is(err, kube.ErrForbidden):
		return withStatus("forbidden", kube.HTTPStatus(err))
	case errors.Is(err, kube.ErrUnauthorized):
		return withStatus("unauthorized", kube.HTTPStatus(err))
	case errors.Is(err, kube.ErrUnknownResource), errors.Is(err, kube.ErrUnsupportedVerb):
		return errors.New("unknown resource")
	default:
		return withStatus("request failed", kube.HTTPStatus(err))
	}
}

// withStatus appends the HTTP status to a safe message when one is known.
func withStatus(message string, status int) error {
	if status != 0 {
		return fmt.Errorf("%s (HTTP %d)", message, status)
	}
	return errors.New(message)
}
