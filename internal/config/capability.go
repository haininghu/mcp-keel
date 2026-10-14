package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hvo/mcp-keel/internal/policy"
)

// CapabilityGrant is one configured capability entry: a resource written as it
// appears in the config (as a raw string, canonicalised later per cluster by the
// kube layer, ADR 0012), a verb, and an optional filter.
type CapabilityGrant struct {
	// Resource is the resource identifier exactly as written in the config,
	// for example "pods", "core/pods", "apps/deployments" or "pods/log".
	Resource string
	// Wildcard reports whether Resource is the standalone "*" wildcard.
	Wildcard bool
	// Verb is the requested verb: "get", "list" or the "*" wildcard.
	Verb policy.Verb
	// VerbWildcard reports whether Verb is "*" (allowed only on deny rules).
	VerbWildcard bool
	// Filter carries the optional label, name and namespace-marker filter.
	Filter policy.CapabilityFilter
}

// UnmarshalYAML parses both the scalar form ("resource:verb") and the
// single-key mapping form that attaches a filter:
//
//	"*:get":
//	  labels:
//	    require: ["managed-by=platform"]
//
// Unknown filter keys are rejected so a typo can never silently drop a filter.
func (g *CapabilityGrant) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		return g.parseSpec(node.Value)
	case yaml.MappingNode:
		if len(node.Content) != 2 {
			return fmt.Errorf("capability filter must be a single-key mapping")
		}
		if err := g.parseSpec(node.Content[0].Value); err != nil {
			return err
		}
		filter, err := parseCapabilityFilter(node.Content[1])
		if err != nil {
			return err
		}
		g.Filter = filter
		return nil
	default:
		return fmt.Errorf("capability must be a string or a single-key mapping")
	}
}

// parseSpec splits a "<resource>:<verb>" capability string. Full resource and
// verb validation happens later, with the rule effect in scope (a "*" verb is
// only valid on a deny rule).
func (g *CapabilityGrant) parseSpec(spec string) error {
	resource, verb, ok := strings.Cut(strings.TrimSpace(spec), ":")
	if !ok {
		return fmt.Errorf("capability %q must have the form <resource>:<verb>", spec)
	}
	resource = strings.TrimSpace(resource)
	verb = strings.TrimSpace(verb)
	if resource == "" {
		return fmt.Errorf("capability %q has an empty resource", spec)
	}
	if verb == "" {
		return fmt.Errorf("capability %q has an empty verb", spec)
	}
	g.Resource = resource
	g.Wildcard = resource == "*"
	g.Verb = policy.Verb(verb)
	g.VerbWildcard = verb == "*"
	return nil
}

// parseCapabilityFilter parses the filter mapping of a capability entry. Only
// "labels", "names" and "namespace_marker" keys are accepted.
func parseCapabilityFilter(node *yaml.Node) (policy.CapabilityFilter, error) {
	var filter policy.CapabilityFilter
	if node.Kind != yaml.MappingNode {
		return filter, fmt.Errorf("capability filter must be a mapping")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]
		switch key {
		case "labels":
			labels, err := parseLabelFilter(value)
			if err != nil {
				return filter, fmt.Errorf("labels: %w", err)
			}
			filter.Labels = labels
		case "names":
			names, err := parseNameFilter(value)
			if err != nil {
				return filter, fmt.Errorf("names: %w", err)
			}
			filter.Names = names
		case "namespace_marker":
			if value.Kind != yaml.ScalarNode || value.Value != "allow" {
				return filter, fmt.Errorf(`namespace_marker: only "allow" is accepted`)
			}
			filter.NamespaceMarkerExempt = true
		default:
			return filter, fmt.Errorf("unknown capability filter key %q", key)
		}
	}
	return filter, nil
}

// parseLabelFilter parses a "labels" mapping with "require" and "exclude" keys.
func parseLabelFilter(node *yaml.Node) (policy.LabelFilter, error) {
	var filter policy.LabelFilter
	if node.Kind != yaml.MappingNode {
		return filter, fmt.Errorf("must be a mapping")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]
		switch key {
		case "require":
			if err := value.Decode(&filter.Require); err != nil {
				return filter, fmt.Errorf("require: %w", err)
			}
		case "exclude":
			if err := value.Decode(&filter.Exclude); err != nil {
				return filter, fmt.Errorf("exclude: %w", err)
			}
		default:
			return filter, fmt.Errorf("unknown key %q", key)
		}
	}
	return filter, nil
}

// parseNameFilter parses a "names" mapping with "include" and "exclude" keys.
func parseNameFilter(node *yaml.Node) (policy.NameFilter, error) {
	var filter policy.NameFilter
	if node.Kind != yaml.MappingNode {
		return filter, fmt.Errorf("must be a mapping")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]
		switch key {
		case "include":
			if err := value.Decode(&filter.Include); err != nil {
				return filter, fmt.Errorf("include: %w", err)
			}
		case "exclude":
			if err := value.Decode(&filter.Exclude); err != nil {
				return filter, fmt.Errorf("exclude: %w", err)
			}
		default:
			return filter, fmt.Errorf("unknown key %q", key)
		}
	}
	return filter, nil
}

// validate checks the capability against the resource grammar (ADR 0012, syntax
// only) and the rule effect (a "*" verb is only valid on deny rules).
func (g *CapabilityGrant) validate(effect policy.Effect) error {
	if err := validateResourceSyntax(g.Resource, true); err != nil {
		return err
	}
	if g.Wildcard != (g.Resource == "*") {
		return fmt.Errorf("resource wildcard flag does not match resource %q", g.Resource)
	}
	switch {
	case g.VerbWildcard:
		if effect != policy.EffectDeny {
			return fmt.Errorf(`verb "*" is only allowed on deny rules`)
		}
	case g.Verb != policy.VerbGet && g.Verb != policy.VerbList:
		return fmt.Errorf("verb must be get or list, got %q", g.Verb)
	}
	if err := validateLabelFilter(g.Filter.Labels); err != nil {
		return err
	}
	if err := validateNameFilter(g.Filter.Names); err != nil {
		return err
	}
	return nil
}
