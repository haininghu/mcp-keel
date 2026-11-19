package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/haininghu/mcp-keel/internal/config"
	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
	"github.com/haininghu/mcp-keel/internal/redact"
)

// redactionFor returns the compiled content-redaction engine for a
// (provider, context) pair, building and caching it on first use. Redaction
// resources are canonicalised against that context's discovery, so an engine
// cannot be shared across contexts (ADR 0012, ADR 0015).
//
// An engine built while discovery was partial is used for the request but not
// cached, mirroring policyFor (ADR 0014).
func (s *Server) redactionFor(ctx context.Context, provider, contextName string, cluster Cluster) (*redact.Engine, error) {
	key := policyKey{provider: provider, context: contextName}
	s.policyMu.Lock()
	if engine, ok := s.redactions[key]; ok {
		s.policyMu.Unlock()
		return engine, nil
	}
	s.policyMu.Unlock()

	engine, partial, err := s.buildRedactions(ctx, provider, cluster)
	if err != nil {
		// buildRedactions never returns configuration details, so this is safe
		// to log; it fails closed for the request only.
		s.logger.Error("building redactions failed",
			"provider", provider, "context", contextName)
		return nil, errAuthorizationFailed
	}

	if !partial {
		s.policyMu.Lock()
		if existing, ok := s.redactions[key]; ok {
			engine = existing
		} else {
			s.redactions[key] = engine
		}
		s.policyMu.Unlock()
	}
	return engine, nil
}

// buildRedactions turns the provider's configured redaction rules into
// redact.Rules and compiles them. Resources follow the capability logic: an
// unresolvable or ambiguous resource is skipped with a warning, and a rule that
// listed resources but resolved none is dropped entirely. Dropping such a rule
// is the only safe choice: a rule with an empty Resources list would match
// every resource (ADR 0015).
//
// The bool reports that discovery was partial, so the caller does not cache the
// result.
func (s *Server) buildRedactions(ctx context.Context, provider string, cluster Cluster) (*redact.Engine, bool, error) {
	providerCfg, ok := s.providers[provider]
	if !ok {
		return nil, false, fmt.Errorf("unknown provider %q", provider)
	}

	partial := false
	rules := make([]redact.Rule, 0, len(providerCfg.Redactions))
	for i := range providerCfg.Redactions {
		configured := &providerCfg.Redactions[i]
		resources := make([]policy.Resource, 0, len(configured.Resources))
		for _, raw := range configured.Resources {
			// The exact resource "prometheus" maps to the synthetic resource
			// before discovery (ADR 0017); otherwise a Prometheus Operator CRD
			// could silently shadow the rule.
			if raw == policy.PrometheusResourceName {
				resources = append(resources, policy.PrometheusResource())
				continue
			}
			res, wildcard, err := cluster.Canonicalize(ctx, raw)
			if err != nil {
				if errors.Is(err, kube.ErrPartialDiscovery) {
					partial = true
				}
				s.logger.Warn("skipping unresolvable redaction resource",
					"provider", provider, "rule", i, "resource", raw)
				continue
			}
			if wildcard || res.Name == "" {
				s.logger.Warn("skipping wildcard redaction resource",
					"provider", provider, "rule", i, "resource", raw)
				continue
			}
			resources = append(resources, res)
		}
		if len(configured.Resources) > 0 && len(resources) == 0 {
			s.logger.Warn("dropping redaction rule with no resolvable resources",
				"provider", provider, "rule", i)
			continue
		}
		rules = append(rules, redact.Rule{
			Resources:  resources,
			Namespaces: configured.Namespaces,
			Names:      configured.Names,
			Labels:     configured.Labels,
			Fields:     redactFields(configured.Fields),
			Replace:    redactReplacements(configured.Replace),
		})
	}

	engine, err := redact.Build(rules)
	if err != nil {
		return nil, partial, err
	}
	return engine, partial, nil
}

// redactFields maps configured field operations to their engine form.
func redactFields(fields []config.FieldRedaction) []redact.FieldOp {
	if len(fields) == 0 {
		return nil
	}
	out := make([]redact.FieldOp, len(fields))
	for i := range fields {
		out[i] = redact.FieldOp{
			Path:   fields[i].Path,
			Action: redact.Action(fields[i].Action),
			Marker: markerValue(fields[i].Marker),
		}
	}
	return out
}

// redactReplacements maps configured textual replacements to their engine form.
func redactReplacements(replacements []config.ReplaceRedaction) []redact.ReplaceOp {
	if len(replacements) == 0 {
		return nil
	}
	out := make([]redact.ReplaceOp, len(replacements))
	for i := range replacements {
		out[i] = redact.ReplaceOp{
			Text:    replacements[i].Text,
			Pattern: replacements[i].Pattern,
			Marker:  markerValue(replacements[i].Marker),
		}
	}
	return out
}

// markerValue returns the configured marker override, or "" to select the
// engine's default marker.
func markerValue(marker *string) string {
	if marker == nil {
		return ""
	}
	return *marker
}

// redactionMatch builds the redaction match for a fetched object.
func redactionMatch(res policy.Resource, namespace string, namespaced bool, name string, labels map[string]string) redact.Match {
	return redact.Match{
		Resource:   res,
		Namespace:  namespace,
		Namespaced: namespaced,
		Name:       name,
		Labels:     policy.LabelSet{Known: true, Values: labels},
	}
}
