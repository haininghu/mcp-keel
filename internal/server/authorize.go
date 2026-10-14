package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/hvo/mcp-keel/internal/kube"
	"github.com/hvo/mcp-keel/internal/policy"
)

// policyFor returns the compiled policy for a (provider, context) pair, building
// and caching it on first use. The policy is canonicalised against that
// context's discovery, so it cannot be shared across contexts (ADR 0012).
//
// A policy built while discovery was partial is used for the request but not
// cached: a group that failed discovery could add resources later, and caching
// would keep them blocked until restart. Once discovery is complete the policy
// is cached again (ADR 0014).
func (s *Server) policyFor(ctx context.Context, provider, contextName string, cluster Cluster) (*policy.Policy, error) {
	key := policyKey{provider: provider, context: contextName}
	s.policyMu.Lock()
	if compiled, ok := s.policyByKey[key]; ok {
		s.policyMu.Unlock()
		return compiled, nil
	}
	s.policyMu.Unlock()

	compiled, partial, err := s.buildPolicy(ctx, provider, cluster)
	if err != nil {
		// buildPolicy never returns configuration details, so this is safe to
		// log; it fails closed for the request only.
		s.logger.Error("building policy failed",
			"provider", provider, "context", contextName)
		return nil, errAuthorizationFailed
	}

	if !partial {
		s.policyMu.Lock()
		if existing, ok := s.policyByKey[key]; ok {
			compiled = existing
		} else {
			s.policyByKey[key] = compiled
		}
		s.policyMu.Unlock()
	}
	return compiled, nil
}

// buildPolicy turns the provider's configured rules into policy.RuleSpecs and
// compiles them. Capabilities whose resource cannot be canonicalised against
// this context's discovery are skipped with a warning instead of invalidating
// the whole policy: a single unresolvable (or partial-discovery) resource must
// deny only itself, not every request of the provider/context (ADR 0014).
//
// A rule whose capabilities all fail to resolve is dropped: an allow rule
// grants nothing, and a deny rule with configured capabilities must not
// silently become a blanket deny. A deny rule that had no capabilities to begin
// with stays a scope-only deny.
//
// The bool reports that discovery was partial, so the caller does not cache the
// result.
func (s *Server) buildPolicy(ctx context.Context, provider string, cluster Cluster) (*policy.Policy, bool, error) {
	providerCfg, ok := s.providers[provider]
	if !ok {
		return nil, false, fmt.Errorf("unknown provider %q", provider)
	}

	partial := false
	specs := make([]policy.RuleSpec, 0, len(providerCfg.Rules))
	for i, rule := range providerCfg.Rules {
		grantSpecs := make([]policy.CapabilityGrant, 0, len(rule.Capabilities))
		for _, grant := range rule.Capabilities {
			compiled := policy.CapabilityGrant{
				ResourceWildcard: grant.Wildcard,
				Verb:             grant.Verb,
				VerbWildcard:     grant.VerbWildcard,
				Filter:           grant.Filter,
			}
			if !grant.Wildcard {
				res, _, err := cluster.Canonicalize(ctx, grant.Resource)
				if err != nil {
					if errors.Is(err, kube.ErrPartialDiscovery) {
						partial = true
					}
					s.logger.Warn("skipping unresolvable capability",
						"provider", provider, "rule", i, "capability", grant.Resource)
					continue
				}
				compiled.Resource = res
			}
			grantSpecs = append(grantSpecs, compiled)
		}
		if len(rule.Capabilities) > 0 && len(grantSpecs) == 0 {
			s.logger.Warn("dropping rule with no resolvable capabilities",
				"provider", provider, "rule", i, "effect", string(rule.Effect))
			continue
		}
		specs = append(specs, policy.RuleSpec{
			Namespaces:   rule.Namespaces,
			Effect:       rule.Effect,
			Capabilities: grantSpecs,
		})
	}

	sensitive := make([]policy.Resource, 0, len(s.cfg.Server.AdditionalSensitiveResources))
	for _, raw := range s.cfg.Server.AdditionalSensitiveResources {
		resources, err := cluster.CanonicalizeAll(ctx, raw)
		if err != nil {
			if errors.Is(err, kube.ErrPartialDiscovery) {
				partial = true
			}
			s.logger.Warn("skipping unresolvable additional sensitive resource",
				"provider", provider, "resource", raw)
			continue
		}
		sensitive = append(sensitive, resources...)
	}
	compiled, err := policy.Build(specs, sensitive)
	if err != nil {
		return nil, partial, err
	}
	return compiled, partial, nil
}

// markerEnabled reports whether the optional namespace-marker overlay is active.
func (s *Server) markerEnabled() bool {
	return s.cfg.Server.NamespaceMarker.Enabled
}

// markerLabel returns the configured namespace marker label.
func (s *Server) markerLabel() string {
	return s.cfg.Server.NamespaceMarker.Label
}
