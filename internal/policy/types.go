package policy

// Verb is a read-only Kubernetes operation that the policy can authorize.
type Verb string

const (
	// VerbGet authorizes reading a single object by name.
	VerbGet Verb = "get"
	// VerbList authorizes listing objects.
	VerbList Verb = "list"
	// VerbWildcard matches every verb. It is only valid on deny rules (ADR 0011).
	VerbWildcard Verb = "*"
)

// Effect is the outcome a matching rule produces.
type Effect string

const (
	// EffectAllow grants a matched capability.
	EffectAllow Effect = "allow"
	// EffectDeny refuses a matched capability.
	EffectDeny Effect = "deny"
)

// Resource is a canonical Kubernetes resource identifier. Group, Name and
// Subresource are already resolved through discovery (ADR 0012): the core group
// is the empty string and Name is the plural resource name ("pods",
// "deployments"). Subresource is empty unless the resource is a subresource such
// as "pods/log".
type Resource struct {
	Group       string
	Name        string
	Subresource string
}

// String returns the canonical "[group/]name[/subresource]" form. The core group
// is rendered without a prefix: "pods", "pods/log", "apps/deployments".
func (r Resource) String() string {
	name := r.Name
	if r.Group != "" {
		name = r.Group + "/" + name
	}
	if r.Subresource != "" {
		name += "/" + r.Subresource
	}
	return name
}

// IsSubresource reports whether the resource addresses a subresource such as
// "pods/log".
func (r Resource) IsSubresource() bool {
	return r.Subresource != ""
}

// LabelSet carries the labels of the object under evaluation together with
// whether they are known. An unknown set makes every label filter fail closed.
type LabelSet struct {
	// Known reports whether Values reflects the target object's labels.
	Known bool
	// Values is the object's label map.
	Values map[string]string
}

// LabelFilter selects objects by labels. Each entry is either a bare "key"
// (matches key presence) or "key=value" (matches the exact, case-sensitive
// value). Require lists entries that must all match; Exclude lists entries that
// must not match and wins over Require.
type LabelFilter struct {
	Require []string `yaml:"require"`
	Exclude []string `yaml:"exclude"`
}

// NameFilter selects objects by metadata.name using doublestar globs. When
// Include is non-empty the name must match at least one glob; Exclude requires
// the name to match none and wins over Include.
type NameFilter struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// CapabilityFilter narrows a capability grant. Labels and Names are match
// predicates evaluated against the target object. NamespaceMarkerExempt only
// records that the grant opts out of the namespace-marker overlay; the marker
// check itself is not part of this package.
type CapabilityFilter struct {
	Labels                LabelFilter `yaml:"labels"`
	Names                 NameFilter  `yaml:"names"`
	NamespaceMarkerExempt bool        `yaml:"namespace_marker_exempt"`
}

// CapabilityGrant is one "resource:verb" entry of a rule with an optional
// filter. ResourceWildcard and VerbWildcard represent the "*" forms; a grant may
// also express the resource wildcard as Resource.Name == "*".
type CapabilityGrant struct {
	Resource         Resource
	ResourceWildcard bool
	Verb             Verb
	VerbWildcard     bool
	Filter           CapabilityFilter
}

// RuleSpec is an ordered policy rule. Namespaces is non-empty: each entry is a
// doublestar glob matched against a namespaced request, and the literal empty
// string selects cluster-scoped requests (ADR 0004). Capabilities lists the
// granted or denied "resource:verb" entries; a deny rule with none denies every
// capability in its scope.
type RuleSpec struct {
	Namespaces   []string
	Effect       Effect
	Capabilities []CapabilityGrant
}

// Request is a single authorization request against an already-canonical
// resource.
type Request struct {
	// Namespace is the request's namespace. It is empty for a cluster-scoped
	// resource; an all-namespaces list is evaluated per item (ADR 0004).
	Namespace string
	// Namespaced reports whether the resolved resource is namespaced. It comes
	// from discovery, not from the namespace string.
	Namespaced bool
	// Resource is the canonical resource under evaluation.
	Resource Resource
	// Verb is the requested verb.
	Verb Verb
	// Name is the object name for get or the per-item name for list.
	Name string
	// Labels is the target object's label set.
	Labels LabelSet
}

// Decision is the result of evaluating a request. Matched reports whether a rule
// applied; Allowed reports whether that rule granted access. Reason is a short,
// stable explanation suitable for server-side logging. NamespaceMarkerExempt
// reports whether the winning capability grant opted out of the namespace-marker
// overlay; the marker check itself (the namespace's label) is performed by the
// server/kube layer, not by this package.
type Decision struct {
	Allowed               bool
	Matched               bool
	Reason                string
	NamespaceMarkerExempt bool
}

const (
	// ReasonAllowed is set when an allow rule granted the request.
	ReasonAllowed = "allowed by rule"

	// ReasonDenied is set when a deny rule refused the request.
	ReasonDenied = "denied by rule"
	// ReasonNoMatchingRule is set when no rule's scope matched the request.
	ReasonNoMatchingRule = "no matching rule"
	// ReasonCapabilityNotGranted is set when a rule's scope matched but no
	// capability matched the requested resource and verb.
	ReasonCapabilityNotGranted = "capability not granted"
	// ReasonFilterNotMet is set when a capability matched the requested resource
	// and verb but its filter did not pass.
	ReasonFilterNotMet = "filter not met"
)
