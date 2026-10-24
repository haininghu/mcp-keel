// Package kube is the Kubernetes backend of mcp-keel. It loads a kubeconfig,
// builds a dynamic and a discovery client per (provider, context), tolerates
// partial discovery failures with a short-lived cache, and canonicalises
// resource identifiers exactly as specified by ADR 0012. It imports
// internal/config and internal/policy but no server code, and it never logs or
// returns credentials or raw API response bodies (ADR 0007, ADR 0014).
package kube

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/haininghu/mcp-keel/internal/config"
)

// Registry resolves providers and contexts to cached cluster clients. It is
// built once at startup and is safe for concurrent use. The providers map is
// immutable after NewRegistry.
type Registry struct {
	cfg    *config.Config
	logger *slog.Logger

	providers map[string]*provider
}

// provider holds the immutable per-provider configuration plus its lazily built
// cluster cache.
type provider struct {
	cfg   *config.ProviderConfig
	rules *clientcmd.ClientConfigLoadingRules

	mu       sync.Mutex
	clusters map[string]*Cluster
}

// NewRegistry loads the kubeconfig(s), validates every provider's contexts and
// returns a ready registry. A literal context that does not exist in the
// kubeconfig is an error; a glob with zero matches is a warning (ADR 0014).
func NewRegistry(cfg *config.Config, logger *slog.Logger) (*Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kube: config must not be nil")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	registry := &Registry{
		cfg:       cfg,
		logger:    logger,
		providers: make(map[string]*provider, len(cfg.Providers)),
	}
	for i := range cfg.Providers {
		providerCfg := &cfg.Providers[i]
		rules := loadingRules(providerCfg.Kubeconfig, cfg.Server.Kubeconfig)
		raw, err := rules.Load()
		if err != nil {
			return nil, fmt.Errorf("provider %q: load kubeconfig: %w", providerCfg.Name, err)
		}
		if err := validateContexts(providerCfg.Name, providerCfg.Contexts, raw.Contexts, logger); err != nil {
			return nil, err
		}
		registry.providers[providerCfg.Name] = &provider{
			cfg:      providerCfg,
			rules:    rules,
			clusters: make(map[string]*Cluster),
		}
	}
	return registry, nil
}

// Cluster returns the cached cluster for provider and context. It fails when
// the provider is unknown or the context does not match the provider's
// contexts. An unreadable kubeconfig or a context absent from the kubeconfig
// also fails closed.
func (r *Registry) Cluster(providerName, contextName string) (*Cluster, error) {
	p, ok := r.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, providerName)
	}
	if !p.matchesContext(contextName) {
		return nil, fmt.Errorf("%w: %q not in provider %q", ErrUnknownContext, contextName, providerName)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if cluster, ok := p.clusters[contextName]; ok {
		return cluster, nil
	}
	cluster, err := r.buildCluster(p, contextName)
	if err != nil {
		return nil, err
	}
	p.clusters[contextName] = cluster
	return cluster, nil
}

// Contexts returns the concrete context names present in the provider's
// kubeconfig that match its configured contexts globs, sorted ascending. It
// reads the kubeconfig through the same loading rules as Cluster and returns
// only names; kubeconfig contents, server URLs and credentials are never
// exposed. A glob with no match contributes nothing; an unreadable kubeconfig
// is an error wrapping the load failure.
func (r *Registry) Contexts(providerName string) ([]string, error) {
	p, ok := r.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, providerName)
	}
	raw, err := p.rules.Load()
	if err != nil {
		return nil, fmt.Errorf("provider %q: load kubeconfig: %w", providerName, err)
	}
	names := make([]string, 0, len(raw.Contexts))
	for name := range raw.Contexts {
		if p.matchesContext(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// matchesContext reports whether name is selected by one of the provider's
// context globs.
func (p *provider) matchesContext(name string) bool {
	for _, pattern := range p.cfg.Contexts {
		if ok, err := doublestar.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

// buildCluster builds the dynamic and discovery clients for one context. The
// dynamic client uses request_timeout, the discovery client discovery_timeout;
// both share the same credentials and QPS/Burst settings.
func (r *Registry) buildCluster(p *provider, contextName string) (*Cluster, error) {
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(p.rules, overrides)
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("provider %q: context %q: %w", p.cfg.Name, contextName, err)
	}
	restConfig.QPS = float32(r.providerQPS(p))
	restConfig.Burst = r.providerBurst(p)
	restConfig.Timeout = time.Duration(r.providerRequestTimeout(p))

	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("provider %q: context %q: build dynamic client: %w", p.cfg.Name, contextName, err)
	}
	discoveryConfig := rest.CopyConfig(restConfig)
	discoveryConfig.Timeout = time.Duration(r.providerDiscoveryTimeout(p))
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(discoveryConfig)
	if err != nil {
		return nil, fmt.Errorf("provider %q: context %q: build discovery client: %w", p.cfg.Name, contextName, err)
	}
	return &Cluster{
		provider: p.cfg.Name,
		context:  contextName,
		dynamic:  dynamicClient,
		source: discoveryClientSource{
			client: discoveryClient,
			logger: r.logger,
		},
		cacheTTL: time.Duration(r.providerCacheTTL(p)),
		now:      time.Now,
	}, nil
}

// loadingRules builds client-go loading rules honouring the kubeconfig path
// precedence: provider.kubeconfig > server.kubeconfig > $KUBECONFIG >
// ~/.kube/config (ADR 0007). Paths come only from configuration.
func loadingRules(providerPath, serverPath string) *clientcmd.ClientConfigLoadingRules {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	switch {
	case providerPath != "":
		rules.ExplicitPath = providerPath
	case serverPath != "":
		rules.ExplicitPath = serverPath
	}
	return rules
}

// validateContexts checks the provider's contexts against the loaded
// kubeconfig. A literal context that does not exist is an error; a glob with
// zero matches is a warning (ADR 0014). No cluster call is made.
func validateContexts(providerName string, patterns []string, contexts map[string]*clientcmdapi.Context, logger *slog.Logger) error {
	for _, pattern := range patterns {
		if isLiteralPattern(pattern) {
			if _, ok := contexts[pattern]; !ok {
				return fmt.Errorf("provider %q: context %q not found in kubeconfig", providerName, pattern)
			}
			continue
		}
		matched := false
		for name := range contexts {
			if ok, err := doublestar.Match(pattern, name); err == nil && ok {
				matched = true
				break
			}
		}
		if !matched {
			logger.Warn("provider context glob matches no kubeconfig context",
				"provider", providerName, "pattern", pattern)
		}
	}
	return nil
}

// isLiteralPattern reports whether pattern contains no glob metacharacter and
// therefore names exactly one context.
func isLiteralPattern(pattern string) bool {
	return !strings.ContainsAny(pattern, "*?[]{}")
}

func (r *Registry) providerQPS(p *provider) float64 {
	if p.cfg.QPS != nil {
		return *p.cfg.QPS
	}
	return r.cfg.Server.QPS
}

func (r *Registry) providerBurst(p *provider) int {
	if p.cfg.Burst != nil {
		return *p.cfg.Burst
	}
	return r.cfg.Server.Burst
}

func (r *Registry) providerRequestTimeout(p *provider) config.Duration {
	if p.cfg.RequestTimeout != nil {
		return *p.cfg.RequestTimeout
	}
	return r.cfg.Server.RequestTimeout
}

func (r *Registry) providerDiscoveryTimeout(p *provider) config.Duration {
	if p.cfg.DiscoveryTimeout != nil {
		return *p.cfg.DiscoveryTimeout
	}
	return r.cfg.Server.DiscoveryTimeout
}

func (r *Registry) providerCacheTTL(p *provider) config.Duration {
	if p.cfg.DiscoveryCacheTTL != nil {
		return *p.cfg.DiscoveryCacheTTL
	}
	return r.cfg.Server.DiscoveryCacheTTL
}
