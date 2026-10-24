// Package policy implements the backend-agnostic, deny-by-default authorization
// engine of mcp-keel. It evaluates ordered firewall-style rules (ADR 0011)
// against already-canonical resources (ADR 0012) and depends on nothing but the
// standard library and doublestar. Discovery, canonicalisation and YAML parsing
// live elsewhere.
package policy

import (
	"fmt"
	"slices"

	"github.com/bmatcuk/doublestar/v4"
)

// Policy is a compiled, immutable rule set plus the sensitive resource set. A
// Policy is safe for concurrent use once built.
type Policy struct {
	rules     []compiledRule
	sensitive map[Resource]struct{}
}

type compiledRule struct {
	namespaceGlobs []string
	clusterMarker  bool
	effect         Effect
	capabilities   []compiledGrant
}

type compiledGrant struct {
	resource         Resource
	resourceWildcard bool
	verb             Verb
	verbWildcard     bool
	filter           CapabilityFilter
}

// BuiltinSensitive returns the canonical built-in sensitive resource set that an
// allow "*" must never match (ADR 0004). Build always includes these entries;
// callers may add to the set but can never remove them.
func BuiltinSensitive() []Resource {
	return []Resource{
		{Name: "secrets"},
		{Name: "serviceaccounts"},
		{Name: "configmaps"},
		{Group: "rbac.authorization.k8s.io", Name: "roles"},
		{Group: "rbac.authorization.k8s.io", Name: "rolebindings"},
		{Group: "rbac.authorization.k8s.io", Name: "clusterroles"},
		{Group: "rbac.authorization.k8s.io", Name: "clusterrolebindings"},
	}
}

// Build validates specs and additionalSensitive and compiles them into a Policy.
// The additionalSensitive slice holds extra canonical resources that an allow
// "*" must never match; it is unioned with BuiltinSensitive and can only extend
// the safe default, never weaken it. Build fails closed: any invalid effect,
// namespace pattern, capability, filter or sensitive entry is an error.
func Build(specs []RuleSpec, additionalSensitive []Resource) (*Policy, error) {
	p := &Policy{
		rules:     make([]compiledRule, 0, len(specs)),
		sensitive: make(map[Resource]struct{}, len(additionalSensitive)+len(BuiltinSensitive())),
	}
	for _, res := range BuiltinSensitive() {
		p.sensitive[res] = struct{}{}
	}
	for _, res := range additionalSensitive {
		if err := validateSensitive(res); err != nil {
			return nil, err
		}
		p.sensitive[res] = struct{}{}
	}
	for i, spec := range specs {
		rule, err := compileRule(spec)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		p.rules = append(p.rules, rule)
	}
	return p, nil
}

func validateSensitive(res Resource) error {
	if res.Name == "" {
		return fmt.Errorf("sensitive resource must not be empty")
	}
	if res.Name == "*" {
		return fmt.Errorf("sensitive resource must not be a wildcard")
	}
	return nil
}

func compileRule(spec RuleSpec) (compiledRule, error) {
	if spec.Effect != EffectAllow && spec.Effect != EffectDeny {
		return compiledRule{}, fmt.Errorf("unknown effect %q", spec.Effect)
	}
	if len(spec.Namespaces) == 0 {
		return compiledRule{}, fmt.Errorf("namespaces must not be empty")
	}
	rule := compiledRule{effect: spec.Effect}
	for _, ns := range spec.Namespaces {
		if ns == "" {
			rule.clusterMarker = true
			continue
		}
		if !doublestar.ValidatePattern(ns) {
			return compiledRule{}, fmt.Errorf("invalid namespace pattern %q", ns)
		}
		rule.namespaceGlobs = append(rule.namespaceGlobs, ns)
	}
	if spec.Effect == EffectAllow && len(spec.Capabilities) == 0 {
		return compiledRule{}, fmt.Errorf("allow rule must list at least one capability")
	}
	rule.capabilities = make([]compiledGrant, 0, len(spec.Capabilities))
	for i := range spec.Capabilities {
		compiled, err := compileGrant(&spec.Capabilities[i], spec.Effect)
		if err != nil {
			return compiledRule{}, err
		}
		rule.capabilities = append(rule.capabilities, compiled)
	}
	return rule, nil
}

func compileGrant(grant *CapabilityGrant, effect Effect) (compiledGrant, error) {
	compiled := compiledGrant{filter: grant.Filter}

	resource := grant.Resource
	resourceWildcard := grant.ResourceWildcard
	if resource.Name == "*" {
		// Check the original resource before normalising: "apps/*" and "*/log"
		// are not wildcard forms and must not silently become a full wildcard
		// (ADR 0004).
		if resource.Group != "" || resource.Subresource != "" {
			return compiledGrant{}, fmt.Errorf("wildcard resource must not name a group or subresource")
		}
		resourceWildcard = true
		resource = Resource{}
	}
	if resourceWildcard {
		if resource != (Resource{}) {
			return compiledGrant{}, fmt.Errorf("wildcard resource must not name a resource")
		}
	} else if resource.Name == "" {
		return compiledGrant{}, fmt.Errorf("capability resource must not be empty")
	}
	compiled.resource = resource
	compiled.resourceWildcard = resourceWildcard

	verb := grant.Verb
	verbWildcard := grant.VerbWildcard
	if verb == VerbWildcard {
		verbWildcard = true
		verb = ""
	}
	if verbWildcard {
		if effect != EffectDeny {
			return compiledGrant{}, fmt.Errorf(`"*" verb is only allowed on deny rules`)
		}
	} else if verb != VerbGet && verb != VerbList {
		return compiledGrant{}, fmt.Errorf("unknown verb %q", verb)
	}
	compiled.verb = verb
	compiled.verbWildcard = verbWildcard

	if err := validateNameFilter(grant.Filter.Names); err != nil {
		return compiledGrant{}, err
	}
	if err := validateLabelFilter(grant.Filter.Labels); err != nil {
		return compiledGrant{}, err
	}
	return compiled, nil
}

func validateNameFilter(filter NameFilter) error {
	for _, pattern := range filter.Include {
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("invalid names.include pattern %q", pattern)
		}
	}
	for _, pattern := range filter.Exclude {
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("invalid names.exclude pattern %q", pattern)
		}
	}
	return nil
}

func validateLabelFilter(filter LabelFilter) error {
	for _, entry := range filter.Require {
		if entry == "" {
			return fmt.Errorf("empty labels.require entry")
		}
		if slices.Contains(filter.Exclude, entry) {
			return fmt.Errorf("label %q is both required and excluded", entry)
		}
	}
	for _, entry := range filter.Exclude {
		if entry == "" {
			return fmt.Errorf("empty labels.exclude entry")
		}
	}
	return nil
}
