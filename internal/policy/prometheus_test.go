package policy

import "testing"

func TestPrometheusVerbPairing(t *testing.T) {
	prom := PrometheusResource()

	allowStarGet := RuleSpec{
		Namespaces: []string{"monitoring"},
		Effect:     EffectAllow,
		Capabilities: []CapabilityGrant{{
			ResourceWildcard: true, Verb: VerbGet,
		}},
	}
	allowPromGet := RuleSpec{
		Namespaces:   []string{"monitoring"},
		Effect:       EffectAllow,
		Capabilities: []CapabilityGrant{{Resource: prom, Verb: VerbGet}},
	}
	allowPromQuery := RuleSpec{
		Namespaces:   []string{"monitoring"},
		Effect:       EffectAllow,
		Capabilities: []CapabilityGrant{{Resource: prom, Verb: VerbQuery}},
	}
	allowPromRange := RuleSpec{
		Namespaces:   []string{"monitoring"},
		Effect:       EffectAllow,
		Capabilities: []CapabilityGrant{{Resource: prom, Verb: VerbRange}},
	}

	cases := []struct {
		name  string
		specs []RuleSpec
		verb  Verb
		want  bool
	}{
		{name: "allow *:get never grants a query", specs: []RuleSpec{allowStarGet}, verb: VerbQuery, want: false},
		{name: "prometheus:get never grants a query", specs: []RuleSpec{allowPromGet}, verb: VerbQuery, want: false},
		{name: "prometheus:query grants query only", specs: []RuleSpec{allowPromQuery}, verb: VerbQuery, want: true},
		{name: "prometheus:query does not grant range", specs: []RuleSpec{allowPromQuery}, verb: VerbRange, want: false},
		{name: "prometheus:range grants range only", specs: []RuleSpec{allowPromRange}, verb: VerbRange, want: true},
		{name: "prometheus:range does not grant query", specs: []RuleSpec{allowPromRange}, verb: VerbQuery, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Build(tc.specs, nil)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			req := Request{Namespace: "monitoring", Namespaced: true, Resource: prom, Verb: tc.verb, Name: "main"}
			if got := p.Evaluate(&req); got.Allowed != tc.want {
				t.Fatalf("Evaluate(%s) = %+v, want allowed=%v", tc.verb, got, tc.want)
			}
		})
	}
}

func TestAllowWildcardNeverMatchesPrometheus(t *testing.T) {
	specs := []RuleSpec{{
		Namespaces: []string{"*"},
		Effect:     EffectAllow,
		Capabilities: []CapabilityGrant{{
			ResourceWildcard: true, Verb: VerbGet,
		}},
	}}
	p, err := Build(specs, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	prom := PrometheusResource()
	// Defense in depth: an allow "*" never matches the synthetic resource, even
	// for get/list (the resource is in the built-in sensitive set).
	for _, verb := range []Verb{VerbGet, VerbList} {
		req := Request{Namespace: "monitoring", Namespaced: true, Resource: prom, Verb: verb, Name: "main"}
		if got := p.Evaluate(&req); got.Allowed {
			t.Fatalf("allow * granted %s:%s", prom, verb)
		}
	}
}

func TestDenyPrometheusExpansionCoversQueryAndRange(t *testing.T) {
	// buildPolicy expands a deny "prometheus:*" into two synthetic grants
	// (query and range). This mirrors that expansion at the policy level.
	prom := PrometheusResource()
	specs := []RuleSpec{
		{
			Namespaces: []string{"monitoring"},
			Effect:     EffectDeny,
			Capabilities: []CapabilityGrant{
				{Resource: prom, Verb: VerbQuery},
				{Resource: prom, Verb: VerbRange},
			},
		},
		{
			Namespaces: []string{"monitoring"},
			Effect:     EffectAllow,
			Capabilities: []CapabilityGrant{
				{Resource: prom, Verb: VerbQuery},
				{Resource: prom, Verb: VerbRange},
			},
		},
	}
	p, err := Build(specs, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	for _, verb := range []Verb{VerbQuery, VerbRange} {
		req := Request{Namespace: "monitoring", Namespaced: true, Resource: prom, Verb: verb, Name: "main"}
		if got := p.Evaluate(&req); got.Allowed {
			t.Fatalf("deny prometheus:* did not deny %s", verb)
		}
		if got, _ := p.PreCheck(&req); got {
			t.Fatalf("deny prometheus:* pre-check proceeded for %s", verb)
		}
	}
}

func TestPrometheusFirstMatchWins(t *testing.T) {
	prom := PrometheusResource()
	denyQuery := RuleSpec{
		Namespaces: []string{"monitoring"},
		Effect:     EffectDeny,
		Capabilities: []CapabilityGrant{{
			Resource: prom, Verb: VerbQuery,
		}},
	}
	allowQuery := RuleSpec{
		Namespaces: []string{"monitoring"},
		Effect:     EffectAllow,
		Capabilities: []CapabilityGrant{{
			Resource: prom, Verb: VerbQuery,
		}},
	}

	pDenyFirst, err := Build([]RuleSpec{denyQuery, allowQuery}, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	req := Request{Namespace: "monitoring", Namespaced: true, Resource: prom, Verb: VerbQuery, Name: "main"}
	if got := pDenyFirst.Evaluate(&req); got.Allowed {
		t.Fatalf("deny before allow granted a query: %+v", got)
	}

	pAllowFirst, err := Build([]RuleSpec{allowQuery, denyQuery}, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if got := pAllowFirst.Evaluate(&req); !got.Allowed {
		t.Fatalf("allow before deny denied a query: %+v", got)
	}
}
