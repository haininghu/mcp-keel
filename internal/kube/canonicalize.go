package kube

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/hvo/mcp-keel/internal/policy"
)

// coreGroupAlias is the reserved input token for the empty (legacy) API group.
// There is no real API group named "core" (ADR 0012).
const coreGroupAlias = "core"

// candidate is one discovery entry flattened into the fields the
// canonicalisation algorithm matches against (ADR 0012). A resource name
// containing a slash ("pods/log") becomes a subresource candidate whose
// resource is the parent plural.
type candidate struct {
	group       string
	resource    string
	subresource string
	kind        string
	singular    string
	shortNames  []string
	namespaced  bool
	verbs       []string
}

// buildCandidates flattens discovery resource lists into candidates, keeping
// the first entry per canonical (group, resource, subresource). The lists may
// contain several versions of the same group; versions are irrelevant because
// the canonical form is versionless.
func buildCandidates(lists []*metav1.APIResourceList) []candidate {
	var out []candidate
	seen := make(map[policy.Resource]struct{})
	for _, list := range lists {
		if list == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range list.APIResources {
			base, sub, _ := strings.Cut(r.Name, "/")
			key := policy.Resource{Group: gv.Group, Name: base, Subresource: sub}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, candidate{
				group:       gv.Group,
				resource:    base,
				subresource: sub,
				kind:        r.Kind,
				singular:    r.SingularName,
				shortNames:  r.ShortNames,
				namespaced:  r.Namespaced,
				verbs:       r.Verbs,
			})
		}
	}
	return out
}

// matchesName reports whether token names the candidate by plural, singular,
// shortname or kind, case-insensitively.
func (c candidate) matchesName(token string) bool {
	if strings.EqualFold(c.resource, token) {
		return true
	}
	if c.singular != "" && strings.EqualFold(c.singular, token) {
		return true
	}
	for _, short := range c.shortNames {
		if strings.EqualFold(short, token) {
			return true
		}
	}
	return c.kind != "" && strings.EqualFold(c.kind, token)
}

// resolveCanonical resolves raw against the discovery state using the algorithm
// of ADR 0012 and returns the canonical, versionless resource. The standalone
// "*" wildcard is handled by the caller and never reaches this function.
func resolveCanonical(st *discoveryState, raw string) (policy.Resource, error) {
	if raw == "" {
		return policy.Resource{}, fmt.Errorf("%w: empty resource", ErrInvalidResource)
	}
	if strings.Contains(raw, "*") {
		return policy.Resource{}, fmt.Errorf("%w: %q: wildcard must stand alone", ErrInvalidResource, raw)
	}
	tokens := strings.Split(raw, "/")
	if len(tokens) > 3 {
		return policy.Resource{}, fmt.Errorf("%w: %q: too many path segments", ErrInvalidResource, raw)
	}
	for _, token := range tokens {
		if token == "" {
			return policy.Resource{}, fmt.Errorf("%w: %q: empty path segment", ErrInvalidResource, raw)
		}
	}
	switch len(tokens) {
	case 1:
		return resolveOne(st, tokens[0])
	case 2:
		return resolveTwo(st, tokens[0], tokens[1])
	default:
		return resolveThree(st, tokens[0], tokens[1], tokens[2])
	}
}

// resolveCanonicalAll returns every canonical resource that raw could name,
// tolerating ambiguity. It mirrors resolveCanonical's grammar but collects all
// matches instead of failing on more than one. It is used to extend the
// sensitive-resource set so an ambiguous name protects every matching group
// (ADR 0004). While discovery is partial only the entries seen so far are
// returned; the caller re-evaluates once discovery completes.
func resolveCanonicalAll(st *discoveryState, raw string) ([]policy.Resource, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty resource", ErrInvalidResource)
	}
	if strings.Contains(raw, "*") {
		return nil, fmt.Errorf("%w: %q: wildcard must stand alone", ErrInvalidResource, raw)
	}
	tokens := strings.Split(raw, "/")
	if len(tokens) > 3 {
		return nil, fmt.Errorf("%w: %q: too many path segments", ErrInvalidResource, raw)
	}
	for _, token := range tokens {
		if token == "" {
			return nil, fmt.Errorf("%w: %q: empty path segment", ErrInvalidResource, raw)
		}
	}

	var matches []policy.Resource
	switch len(tokens) {
	case 1:
		for _, cand := range st.candidates {
			if cand.subresource != "" {
				continue
			}
			if cand.matchesName(tokens[0]) {
				matches = append(matches, policy.Resource{Group: cand.group, Name: cand.resource})
			}
		}
	case 2:
		matches = append(matches, resolveGroupResource(st, tokens[0], tokens[1])...)
		matches = append(matches, resolveResourceSubresource(st, tokens[0], tokens[1])...)
	default:
		group := tokens[0]
		if strings.EqualFold(group, coreGroupAlias) {
			group = ""
		}
		for _, cand := range st.candidates {
			if cand.subresource == "" {
				continue
			}
			if !strings.EqualFold(cand.group, group) {
				continue
			}
			if !cand.matchesName(tokens[1]) {
				continue
			}
			if !strings.EqualFold(cand.subresource, tokens[2]) {
				continue
			}
			matches = append(matches, policy.Resource{Group: cand.group, Name: cand.resource, Subresource: cand.subresource})
		}
	}

	matches = dedupeResources(matches)
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrUnknownResource, raw)
	}
	return matches, nil
}

// resolveOne resolves a single, unqualified token. Zero matches is unknown and
// several matches is ambiguous; while discovery is partial an unqualified name
// is denied because a failed group could have made it ambiguous.
func resolveOne(st *discoveryState, token string) (policy.Resource, error) {
	if st.partial {
		return policy.Resource{}, partialDenied(token)
	}
	matches := make(map[policy.Resource]struct{})
	for _, cand := range st.candidates {
		if cand.subresource != "" {
			continue
		}
		if cand.matchesName(token) {
			matches[policy.Resource{Group: cand.group, Name: cand.resource}] = struct{}{}
		}
	}
	return singleMatch(matches, token)
}

// resolveTwo resolves "a/b" as either group/resource or resource/subresource.
// Exactly one reading must resolve; both or neither is denied. While discovery
// is partial only an unambiguous, explicit group reading is trusted.
func resolveTwo(st *discoveryState, a, b string) (policy.Resource, error) {
	groupReads := resolveGroupResource(st, a, b)
	subReads := resolveResourceSubresource(st, a, b)
	name := a + "/" + b
	if st.partial {
		if len(groupReads) == 1 && len(subReads) == 0 {
			return groupReads[0], nil
		}
		if len(groupReads) > 1 {
			return policy.Resource{}, fmt.Errorf("%w: %q", ErrAmbiguousResource, name)
		}
		return policy.Resource{}, partialDenied(name)
	}
	matches := dedupeResources(append(append([]policy.Resource{}, groupReads...), subReads...))
	switch len(matches) {
	case 0:
		return policy.Resource{}, fmt.Errorf("%w: %q", ErrUnknownResource, name)
	case 1:
		return matches[0], nil
	default:
		return policy.Resource{}, fmt.Errorf("%w: %q", ErrAmbiguousResource, name)
	}
}

// resolveThree resolves "group/resource/subresource", validated end to end.
func resolveThree(st *discoveryState, groupToken, resourceToken, subToken string) (policy.Resource, error) {
	group := groupToken
	if strings.EqualFold(group, coreGroupAlias) {
		group = ""
	}
	name := groupToken + "/" + resourceToken + "/" + subToken
	if st.partial && !knownGroup(st, groupToken) {
		return policy.Resource{}, partialDenied(name)
	}
	var matches []policy.Resource
	for _, cand := range st.candidates {
		if cand.subresource == "" {
			continue
		}
		if !strings.EqualFold(cand.group, group) {
			continue
		}
		if !cand.matchesName(resourceToken) {
			continue
		}
		if !strings.EqualFold(cand.subresource, subToken) {
			continue
		}
		matches = append(matches, policy.Resource{Group: cand.group, Name: cand.resource, Subresource: cand.subresource})
	}
	switch len(dedupeResources(matches)) {
	case 0:
		return policy.Resource{}, fmt.Errorf("%w: %q", ErrUnknownResource, name)
	case 1:
		return matches[0], nil
	default:
		return policy.Resource{}, fmt.Errorf("%w: %q", ErrAmbiguousResource, name)
	}
}

// resolveGroupResource returns the canonical resources matching an explicit
// "group/resource" reading. The "core" token selects the empty group.
func resolveGroupResource(st *discoveryState, groupToken, resourceToken string) []policy.Resource {
	group := groupToken
	if strings.EqualFold(group, coreGroupAlias) {
		group = ""
	}
	var out []policy.Resource
	for _, cand := range st.candidates {
		if cand.subresource != "" {
			continue
		}
		if !strings.EqualFold(cand.group, group) {
			continue
		}
		if cand.matchesName(resourceToken) {
			out = append(out, policy.Resource{Group: cand.group, Name: cand.resource})
		}
	}
	return dedupeResources(out)
}

// resolveResourceSubresource returns the canonical subresources matching a
// "resource/subresource" reading: the first token names a base resource and the
// second a subresource of it.
func resolveResourceSubresource(st *discoveryState, resourceToken, subToken string) []policy.Resource {
	bases := make(map[policy.Resource]struct{})
	for _, cand := range st.candidates {
		if cand.subresource != "" {
			continue
		}
		if cand.matchesName(resourceToken) {
			bases[policy.Resource{Group: cand.group, Name: cand.resource}] = struct{}{}
		}
	}
	var out []policy.Resource
	for _, cand := range st.candidates {
		if cand.subresource == "" {
			continue
		}
		if !strings.EqualFold(cand.subresource, subToken) {
			continue
		}
		base := policy.Resource{Group: cand.group, Name: cand.resource}
		if _, ok := bases[base]; !ok {
			continue
		}
		out = append(out, policy.Resource{Group: cand.group, Name: cand.resource, Subresource: cand.subresource})
	}
	return dedupeResources(out)
}

// knownGroup reports whether token names an API group present in discovery (or
// the "core" alias).
func knownGroup(st *discoveryState, token string) bool {
	if strings.EqualFold(token, coreGroupAlias) {
		return true
	}
	for _, cand := range st.candidates {
		if strings.EqualFold(cand.group, token) {
			return true
		}
	}
	return false
}

// singleMatch returns the sole match or an unknown/ambiguous error.
func singleMatch(matches map[policy.Resource]struct{}, token string) (policy.Resource, error) {
	switch len(matches) {
	case 0:
		return policy.Resource{}, fmt.Errorf("%w: %q", ErrUnknownResource, token)
	case 1:
		for res := range matches {
			return res, nil
		}
	}
	return policy.Resource{}, fmt.Errorf("%w: %q", ErrAmbiguousResource, token)
}

// partialDenied is the fail-closed error for an unqualified name while
// discovery is partial. It satisfies both ErrUnknownResource and
// ErrPartialDiscovery.
func partialDenied(name string) error {
	return fmt.Errorf("%w: %w: %q", ErrUnknownResource, ErrPartialDiscovery, name)
}

// dedupeResources removes duplicate canonical resources, preserving order.
func dedupeResources(in []policy.Resource) []policy.Resource {
	if len(in) < 2 {
		return in
	}
	seen := make(map[policy.Resource]struct{}, len(in))
	out := in[:0]
	for _, res := range in {
		if _, ok := seen[res]; ok {
			continue
		}
		seen[res] = struct{}{}
		out = append(out, res)
	}
	return out
}
