package policy

import "testing"

var (
	pods        = Resource{Name: "pods"}
	deployments = Resource{Group: "apps", Name: "deployments"}
	secrets     = Resource{Name: "secrets"}
	configmaps  = Resource{Name: "configmaps"}
	nodes       = Resource{Name: "nodes"}
	roles       = Resource{Group: "rbac.authorization.k8s.io", Name: "roles"}
	podsLog     = Resource{Name: "pods", Subresource: "log"}
)

func defaultSensitive() []Resource {
	return BuiltinSensitive()
}

func grant(res Resource, verb Verb) CapabilityGrant {
	return CapabilityGrant{Resource: res, Verb: verb}
}

func labels(values map[string]string) LabelSet {
	return LabelSet{Known: true, Values: values}
}

type evalCase struct {
	name      string
	specs     []RuleSpec
	sensitive []Resource
	req       Request
	want      Decision
}

func TestEvaluate(t *testing.T) {
	cases := []evalCase{
		{
			name:  "deny by default when no scope matches",
			specs: []RuleSpec{{Namespaces: []string{"team-a"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonNoMatchingRule},
		},
		{
			name:  "allow on match",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name:  "verbs do not imply each other",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbList},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name: "first match wins: specific deny before broad allow",
			specs: []RuleSpec{
				{Namespaces: []string{"default"}, Effect: EffectDeny, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
				{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
			},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want: Decision{Allowed: false, Matched: true, Reason: ReasonDenied},
		},
		{
			name: "broad allow above a deny shadows it (documented)",
			specs: []RuleSpec{
				{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
				{Namespaces: []string{"default"}, Effect: EffectDeny, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
			},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want: Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name:  "deny without capabilities denies every capability in scope",
			specs: []RuleSpec{{Namespaces: []string{"locked"}, Effect: EffectDeny}},
			req:   Request{Namespace: "locked", Namespaced: true, Resource: secrets, Verb: VerbList},
			want:  Decision{Allowed: false, Matched: true, Reason: ReasonDenied},
		},
		{
			name:  "deny without capabilities does not reach other namespaces",
			specs: []RuleSpec{{Namespaces: []string{"locked"}, Effect: EffectDeny}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonNoMatchingRule},
		},
		{
			name: "deny with capability and matching label filter",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectDeny,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"noai"}}}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p", Labels: labels(map[string]string{"noai": ""})},
			want: Decision{Allowed: false, Matched: true, Reason: ReasonDenied},
		},
		{
			name: "deny with non-matching label filter falls through",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectDeny,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"noai"}}}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p", Labels: labels(map[string]string{})},
			want: Decision{Allowed: false, Matched: false, Reason: ReasonFilterNotMet},
		},
		{
			name: "deny filter fall-through lets a later allow win",
			specs: []RuleSpec{
				{
					Namespaces: []string{"*"}, Effect: EffectDeny,
					Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"noai"}}}}},
				},
				{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
			},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p", Labels: labels(map[string]string{})},
			want: Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name: "names.include positive scoping",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectAllow,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Names: NameFilter{Include: []string{"frontend-*"}}}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "frontend-1"},
			want: Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name: "names.include miss falls through to a later allow",
			specs: []RuleSpec{
				{
					Namespaces: []string{"*"}, Effect: EffectAllow,
					Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Names: NameFilter{Include: []string{"frontend-*"}}}}},
				},
				{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
			},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "backend-1"},
			want: Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name: "names.exclude wins over names.include",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectAllow,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Names: NameFilter{Include: []string{"frontend-*"}, Exclude: []string{"*-debug"}}}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "frontend-debug"},
			want: Decision{Allowed: false, Matched: false, Reason: ReasonFilterNotMet},
		},
		{
			name: "labels.exclude wins over labels.require",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectAllow,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"managed-by=platform"}, Exclude: []string{"noai"}}}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p", Labels: labels(map[string]string{"managed-by": "platform", "noai": ""})},
			want: Decision{Allowed: false, Matched: false, Reason: ReasonFilterNotMet},
		},
		{
			name: "labels require is exact and case-sensitive",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectAllow,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"managed-by=platform"}}}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p", Labels: labels(map[string]string{"managed-by": "Platform"})},
			want: Decision{Allowed: false, Matched: false, Reason: ReasonFilterNotMet},
		},
		{
			name: "unknown labels fail closed for a label filter",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectAllow,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"managed-by=platform"}}}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p", Labels: LabelSet{Known: false}},
			want: Decision{Allowed: false, Matched: false, Reason: ReasonFilterNotMet},
		},
		{
			name:  "allow wildcard reaches ordinary resources",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: deployments, Verb: VerbGet, Name: "d"},
			want:  Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name:  "allow wildcard never reaches secrets",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: secrets, Verb: VerbGet, Name: "s"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name:  "allow wildcard never reaches RBAC",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: roles, Verb: VerbGet, Name: "r"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name:  "allow wildcard never reaches configmaps",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: configmaps, Verb: VerbGet, Name: "c"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name:  "allow wildcard never reaches subresources",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: podsLog, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name:  "deny wildcard reaches sensitive resources",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectDeny, Capabilities: []CapabilityGrant{{ResourceWildcard: true, VerbWildcard: true}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: secrets, Verb: VerbGet, Name: "s"},
			want:  Decision{Allowed: false, Matched: true, Reason: ReasonDenied},
		},
		{
			name:  "deny wildcard reaches subresources",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectDeny, Capabilities: []CapabilityGrant{{ResourceWildcard: true, VerbWildcard: true}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: podsLog, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: false, Matched: true, Reason: ReasonDenied},
		},
		{
			name:  "deny wildcard with explicit verb covers only that verb",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectDeny, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: secrets, Verb: VerbList},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name:  "explicit sensitive naming grants the capability",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(secrets, VerbGet)}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: secrets, Verb: VerbGet, Name: "s"},
			want:  Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name:      "additional sensitive entry protects a wildcard",
			specs:     []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			sensitive: append(defaultSensitive(), deployments),
			req:       Request{Namespace: "default", Namespaced: true, Resource: deployments, Verb: VerbGet, Name: "d"},
			want:      Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name:  "namespace wildcard never matches cluster scope (star)",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespaced: false, Resource: nodes, Verb: VerbGet, Name: "n"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonNoMatchingRule},
		},
		{
			name:  "namespace wildcard never matches cluster scope (doublestar)",
			specs: []RuleSpec{{Namespaces: []string{"**"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespaced: false, Resource: nodes, Verb: VerbGet, Name: "n"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonNoMatchingRule},
		},
		{
			name:  "namespace glob never matches cluster scope",
			specs: []RuleSpec{{Namespaces: []string{"test-*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(nodes, VerbGet)}}},
			req:   Request{Namespaced: false, Resource: nodes, Verb: VerbGet, Name: "n"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonNoMatchingRule},
		},
		{
			name:  "literal empty marker matches cluster scope",
			specs: []RuleSpec{{Namespaces: []string{""}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(nodes, VerbGet)}}},
			req:   Request{Namespaced: false, Resource: nodes, Verb: VerbGet, Name: "n"},
			want:  Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name:  "literal empty marker does not match a namespaced request",
			specs: []RuleSpec{{Namespaces: []string{""}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(nodes, VerbGet)}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: nodes, Verb: VerbGet, Name: "n"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonNoMatchingRule},
		},
		{
			name:  "combined namespace globs and cluster marker",
			specs: []RuleSpec{{Namespaces: []string{"test-*", ""}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespaced: false, Resource: nodes, Verb: VerbGet, Name: "n"},
			want:  Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name:  "empty namespace on a namespaced request fails closed",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonNoMatchingRule},
		},
		{
			name: "namespace marker exemption is reported for an allow grant",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectAllow,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{NamespaceMarkerExempt: true}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want: Decision{Allowed: true, Matched: true, Reason: ReasonAllowed, NamespaceMarkerExempt: true},
		},
		{
			name:  "namespace marker exemption defaults to false for an allow grant",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: true, Matched: true, Reason: ReasonAllowed},
		},
		{
			name: "namespace marker exemption is reported for a deny grant",
			specs: []RuleSpec{{
				Namespaces: []string{"*"}, Effect: EffectDeny,
				Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{NamespaceMarkerExempt: true}}},
			}},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want: Decision{Allowed: false, Matched: true, Reason: ReasonDenied, NamespaceMarkerExempt: true},
		},
		{
			name:  "namespace marker exemption is false for a capability-less deny",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectDeny}},
			req:   Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: false, Matched: true, Reason: ReasonDenied},
		},
		{
			name:  "empty resource never matches an allow wildcard",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			req:   Request{Namespace: "default", Namespaced: true, Verb: VerbGet, Name: "p"},
			want:  Decision{Allowed: false, Matched: false, Reason: ReasonCapabilityNotGranted},
		},
		{
			name: "a filter miss outranks a later capability miss",
			specs: []RuleSpec{
				{
					Namespaces: []string{"*"}, Effect: EffectAllow,
					Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Names: NameFilter{Include: []string{"frontend-*"}}}}},
				},
				{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(deployments, VerbGet)}},
			},
			req:  Request{Namespace: "default", Namespaced: true, Resource: pods, Verb: VerbGet, Name: "backend-1"},
			want: Decision{Allowed: false, Matched: false, Reason: ReasonFilterNotMet},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sensitive := tc.sensitive
			if sensitive == nil {
				sensitive = defaultSensitive()
			}
			p, err := Build(tc.specs, sensitive)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if got := p.Evaluate(tc.req); got != tc.want {
				t.Fatalf("Evaluate(%+v) = %+v, want %+v", tc.req, got, tc.want)
			}
		})
	}
}

func TestBuiltinSensitiveAlwaysEnforced(t *testing.T) {
	specs := []RuleSpec{{
		Namespaces: []string{"*"}, Effect: EffectAllow,
		Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}},
	}}
	p, err := Build(specs, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	for _, res := range BuiltinSensitive() {
		req := Request{Namespace: "default", Namespaced: true, Resource: res, Verb: VerbGet, Name: "x"}
		if got := p.Evaluate(req); got.Allowed {
			t.Errorf("allow wildcard granted built-in sensitive resource %s: %+v", res, got)
		}
	}
}

func TestGrantsAnywhere(t *testing.T) {
	cases := []struct {
		name  string
		specs []RuleSpec
		res   Resource
		verb  Verb
		want  bool
	}{
		{
			name:  "allow wildcard covers list for pods",
			specs: []RuleSpec{{Namespaces: []string{"team-*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbList}}}},
			res:   pods, verb: VerbList, want: true,
		},
		{
			name:  "allow wildcard does not cover sensitive",
			specs: []RuleSpec{{Namespaces: []string{"team-*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbList}}}},
			res:   secrets, verb: VerbList, want: false,
		},
		{
			name:  "explicit get grants get only",
			specs: []RuleSpec{{Namespaces: []string{"team-*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}}},
			res:   pods, verb: VerbGet, want: true,
		},
		{
			name:  "explicit get does not grant list",
			specs: []RuleSpec{{Namespaces: []string{"team-*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}}},
			res:   pods, verb: VerbList, want: false,
		},
		{
			name:  "deny does not count as a grant",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectDeny, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}}},
			res:   pods, verb: VerbGet, want: false,
		},
		{
			name:  "allow wildcard never covers subresources",
			specs: []RuleSpec{{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}}}},
			res:   podsLog, verb: VerbGet, want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Build(tc.specs, nil)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if got := p.GrantsAnywhere(tc.res, tc.verb); got != tc.want {
				t.Fatalf("GrantsAnywhere(%s, %s) = %v, want %v", tc.res, tc.verb, got, tc.want)
			}
		})
	}
}
