package policy

import "github.com/bmatcuk/doublestar/v4"

// Evaluate applies the compiled rules to req in order and returns the first
// applicable rule's decision. A rule applies when its scope matches AND (it is a
// deny rule without capabilities OR one of its capabilities matches the
// requested resource and verb and that capability's filter passes). If no rule
// applies, access is denied (deny-by-default).
func (p *Policy) Evaluate(req *Request) Decision {
	reason := ReasonNoMatchingRule
	for _, rule := range p.rules {
		if !rule.scopeMatches(req) {
			continue
		}

		// A deny rule without capabilities denies every capability in its scope.
		if rule.effect == EffectDeny && len(rule.capabilities) == 0 {
			return Decision{Allowed: false, Matched: true, Reason: ReasonDenied}
		}

		// Best explanation this rule can give if none of its grants applies.
		ruleReason := ReasonCapabilityNotGranted
		for i := range rule.capabilities {
			grant := &rule.capabilities[i]
			if !grant.matchesResource(req.Resource, rule.effect, p.sensitive) {
				continue
			}
			if !grant.matchesVerb(req.Verb, rule.effect) {
				continue
			}
			if !grant.filter.matches(req) {
				// A filter that does not pass means this rule does not apply;
				// evaluation continues (ADR 0011).
				ruleReason = ReasonFilterNotMet
				continue
			}
			exempt := grant.filter.NamespaceMarkerExempt
			if rule.effect == EffectAllow {
				return Decision{Allowed: true, Matched: true, Reason: ReasonAllowed, NamespaceMarkerExempt: exempt}
			}
			return Decision{Allowed: false, Matched: true, Reason: ReasonDenied, NamespaceMarkerExempt: exempt}
		}
		reason = moreRelevantReason(reason, ruleReason)
	}
	return Decision{Allowed: false, Matched: false, Reason: reason}
}

// preStatus classifies a rule for PreCheck: whether it certainly applies,
// might apply once the fetch has produced the object, or cannot apply.
type preStatus int

const (
	// preCannot: the rule cannot apply for this request.
	preCannot preStatus = iota
	// prePossible: the rule could apply after the fetch, because at least one
	// of its conditions (a label filter, or a name filter when the name is not
	// known yet) is not pre-evaluable.
	prePossible
	// preDefinite: every condition that decides the rule's applicability is
	// already known and passes.
	preDefinite
)

// PreCheck reports whether a request should proceed to a cluster fetch. It uses
// only the dimensions known before the fetch (namespace scope, resource, verb
// and, for get, the name); label filters are never pre-evaluable, and name
// filters are pre-evaluable only when req.Name is set.
//
// It is an optimization that never grants and never over-denies:
//
//   - proceed=false with ReasonDenied when a deny rule definitely applies before
//     any rule that could apply;
//   - proceed=true when an allow rule definitely applies, or when
//     GrantsAnywhere(resource, verb) reports that some allow rule could grant;
//   - proceed=false otherwise (deny-by-default).
//
// A rule that only *might* apply blocks any later deny short-circuit, because
// first-match-wins cannot be decided before the fetch.
func (p *Policy) PreCheck(req *Request) (proceed bool, reason string) {
	for _, rule := range p.rules {
		switch rule.preCheckStatus(req, p.sensitive) {
		case preDefinite:
			if rule.effect == EffectDeny {
				return false, ReasonDenied
			}
			return true, ReasonAllowed
		case prePossible:
			// An earlier rule could still win after the fetch: do not
			// short-circuit. Proceed iff some allow rule could grant at all.
			if p.GrantsAnywhere(req.Resource, req.Verb) {
				return true, ""
			}
			return false, ReasonNoMatchingRule
		case preCannot:
			// The rule cannot apply; fall through to the next rule.
		}
	}
	if p.GrantsAnywhere(req.Resource, req.Verb) {
		return true, ""
	}
	return false, ReasonNoMatchingRule
}

// preCheckStatus classifies a rule against the dimensions known before the
// fetch. A deny rule without capabilities applies to every capability in scope.
func (r compiledRule) preCheckStatus(req *Request, sensitive map[Resource]struct{}) preStatus {
	if !r.scopeMatches(req) {
		return preCannot
	}
	if r.effect == EffectDeny && len(r.capabilities) == 0 {
		return preDefinite
	}
	status := preCannot
	for i := range r.capabilities {
		grant := &r.capabilities[i]
		if !grant.matchesResource(req.Resource, r.effect, sensitive) {
			continue
		}
		if !grant.matchesVerb(req.Verb, r.effect) {
			continue
		}
		switch preCheckGrantStatus(&grant.filter, req) {
		case preDefinite:
			return preDefinite
		case prePossible:
			status = prePossible
		case preCannot:
			// The filter cannot match; this grant does not apply.
		}
	}
	return status
}

// preCheckGrantStatus classifies a capability's filter. A name filter is
// pre-evaluable only when the name is known (get); a label filter never is. A
// filter that is pre-evaluable and fails makes the grant inapplicable.
func preCheckGrantStatus(filter *CapabilityFilter, req *Request) preStatus {
	status := preDefinite
	if len(filter.Names.Include) > 0 || len(filter.Names.Exclude) > 0 {
		if req.Name == "" {
			// list evaluates names per item, so this is not pre-evaluable.
			status = prePossible
		} else if !filter.Names.matches(req.Name) {
			return preCannot
		}
	}
	if len(filter.Labels.Require) > 0 || len(filter.Labels.Exclude) > 0 {
		// Labels are only known after the fetch.
		status = prePossible
	}
	return status
}

// GrantsAnywhere reports whether any allow rule has a capability that could
// GrantsAnywhere reports whether any allow rule has a capability that could
// cover res and verb, ignoring namespace scope and capability filters. It backs
// the all-namespaces list pre-check. An allow wildcard still never covers
// subresources or sensitive resources (ADR 0004).
func (p *Policy) GrantsAnywhere(res Resource, verb Verb) bool {
	for _, rule := range p.rules {
		if rule.effect != EffectAllow {
			continue
		}
		for i := range rule.capabilities {
			grant := &rule.capabilities[i]
			if !grant.matchesResource(res, EffectAllow, p.sensitive) {
				continue
			}
			if !grant.matchesVerb(verb, EffectAllow) {
				continue
			}
			return true
		}
	}
	return false
}

// moreRelevantReason returns the more specific of two non-allow reasons. A
// filter miss explains an attempted match, so it outranks a bare capability
// miss, which in turn outranks the deny-by-default reason.
func moreRelevantReason(current, candidate string) string {
	if reasonRank(candidate) > reasonRank(current) {
		return candidate
	}
	return current
}

func reasonRank(reason string) int {
	switch reason {
	case ReasonFilterNotMet:
		return 2
	case ReasonCapabilityNotGranted:
		return 1
	default:
		return 0
	}
}

// scopeMatches reports whether the request's namespace scope is selected by the
// rule. A namespaced request matches through the namespace globs; a
// cluster-scoped request matches only the literal "" marker, never a glob
// (ADR 0004).
func (r compiledRule) scopeMatches(req *Request) bool {
	if !req.Namespaced {
		return r.clusterMarker
	}
	// A namespaced request always names a real namespace; an all-namespaces list
	// is evaluated per item (ADR 0004). An empty namespace fails closed so that
	// no wildcard can ever grant it.
	if req.Namespace == "" {
		return false
	}
	for _, pattern := range r.namespaceGlobs {
		if doublestar.MatchUnvalidated(pattern, req.Namespace) {
			return true
		}
	}
	return false
}

// matchesResource reports whether a capability grant covers the requested
// resource. An empty resource never matches; an allow wildcard never covers
// subresources or sensitive resources; a deny wildcard covers everything
// (ADR 0004).
func (g *compiledGrant) matchesResource(res Resource, effect Effect, sensitive map[Resource]struct{}) bool {
	if res.Name == "" {
		return false
	}
	if !g.resourceWildcard {
		return g.resource == res
	}
	if effect == EffectAllow {
		if res.IsSubresource() {
			return false
		}
		if _, ok := sensitive[res]; ok {
			return false
		}
	}
	return true
}

// matchesVerb reports whether a capability grant covers the requested verb. A
// wildcard verb only exists on deny rules, but the effect is re-checked so a
// malformed grant can never grant implicitly.
func (g *compiledGrant) matchesVerb(verb Verb, effect Effect) bool {
	if g.verb == verb {
		return true
	}
	return g.verbWildcard && effect == EffectDeny
}
