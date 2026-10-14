package server

import (
	"context"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hvo/mcp-keel/internal/config"
	"github.com/hvo/mcp-keel/internal/policy"
)

// listConfiguredRulesInput is the (empty) argument object of
// list_configured_rules.
type listConfiguredRulesInput struct{}

// listClustersInput is the (empty) argument object of list_clusters.
type listClustersInput struct{}

// configuredLabelFilter is the configured labels filter of a capability.
type configuredLabelFilter struct {
	Require []string `json:"require,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// configuredNameFilter is the configured names filter of a capability.
type configuredNameFilter struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// configuredCapability is one configured capability entry.
type configuredCapability struct {
	Resource              string                 `json:"resource"`
	Verb                  string                 `json:"verb"`
	Labels                *configuredLabelFilter `json:"labels,omitempty"`
	Names                 *configuredNameFilter  `json:"names,omitempty"`
	NamespaceMarkerExempt bool                   `json:"namespace_marker_exempt,omitempty"`
}

// configuredRule is one configured rule: its scope, effect and capabilities.
type configuredRule struct {
	Namespaces   []string               `json:"namespaces"`
	Effect       string                 `json:"effect"`
	Capabilities []configuredCapability `json:"capabilities"`
}

// configuredProvider groups the configured rules of one provider.
type configuredProvider struct {
	Provider string           `json:"provider"`
	Rules    []configuredRule `json:"rules"`
}

// listConfiguredRulesOutput is the list_configured_rules envelope.
type listConfiguredRulesOutput struct {
	Providers []configuredProvider `json:"providers"`
}

// clusterProvider names one provider and its configured context patterns.
type clusterProvider struct {
	Provider string   `json:"provider"`
	Contexts []string `json:"contexts"`
}

// listClustersOutput is the list_clusters envelope.
type listClustersOutput struct {
	Providers []clusterProvider `json:"providers"`
}

// handleListConfiguredRules reports the configured rules of providers that opt
// in with policy_read: true, sorted by provider name and preserving rule order.
// It reports configuration only, never effective access (method spec
// list_configured_rules).
func (s *Server) handleListConfiguredRules(_ context.Context, _ *mcp.CallToolRequest, _ listConfiguredRulesInput) (*mcp.CallToolResult, any, error) {
	out := listConfiguredRulesOutput{Providers: []configuredProvider{}}
	for _, name := range s.policyReadProviderNames() {
		provider := s.providers[name]
		rules := make([]configuredRule, len(provider.Rules))
		for i, rule := range provider.Rules {
			rules[i] = configuredRule{
				Namespaces:   rule.Namespaces,
				Effect:       string(rule.Effect),
				Capabilities: configuredCapabilities(rule.Capabilities),
			}
		}
		out.Providers = append(out.Providers, configuredProvider{Provider: name, Rules: rules})
	}
	return jsonResult(out)
}

// handleListClusters reports the provider names and their configured context
// patterns for providers that opt in with policy_read: true, sorted by name
// (method spec list_clusters).
func (s *Server) handleListClusters(_ context.Context, _ *mcp.CallToolRequest, _ listClustersInput) (*mcp.CallToolResult, any, error) {
	out := listClustersOutput{Providers: []clusterProvider{}}
	for _, name := range s.policyReadProviderNames() {
		provider := s.providers[name]
		contexts := append([]string{}, provider.Contexts...)
		out.Providers = append(out.Providers, clusterProvider{Provider: name, Contexts: contexts})
	}
	return jsonResult(out)
}

// policyReadProviderNames returns the names of providers with policy_read set,
// sorted ascending.
func (s *Server) policyReadProviderNames() []string {
	names := make([]string, 0, len(s.providers))
	for name, provider := range s.providers {
		if provider.PolicyRead {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// configuredCapabilities maps configured grants to their JSON form, preserving
// the resource and verb exactly as written.
func configuredCapabilities(grants []config.CapabilityGrant) []configuredCapability {
	out := make([]configuredCapability, len(grants))
	for i, grant := range grants {
		out[i] = configuredCapability{
			Resource:              grant.Resource,
			Verb:                  string(grant.Verb),
			Labels:                configuredLabels(grant.Filter.Labels),
			Names:                 configuredNames(grant.Filter.Names),
			NamespaceMarkerExempt: grant.Filter.NamespaceMarkerExempt,
		}
	}
	return out
}

// configuredLabels returns the configured label filter, or nil when empty.
func configuredLabels(filter policy.LabelFilter) *configuredLabelFilter {
	if len(filter.Require) == 0 && len(filter.Exclude) == 0 {
		return nil
	}
	return &configuredLabelFilter{Require: filter.Require, Exclude: filter.Exclude}
}

// configuredNames returns the configured name filter, or nil when empty.
func configuredNames(filter policy.NameFilter) *configuredNameFilter {
	if len(filter.Include) == 0 && len(filter.Exclude) == 0 {
		return nil
	}
	return &configuredNameFilter{Include: filter.Include, Exclude: filter.Exclude}
}
