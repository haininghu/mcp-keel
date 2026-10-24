package policy

import "testing"

func TestPreCheck(t *testing.T) {
	podsRes := Resource{Name: "pods"}
	secrets := Resource{Name: "secrets"}
	podsLogRes := Resource{Name: "pods", Subresource: "log"}

	defaultReq := Request{Namespace: "ns", Namespaced: true, Resource: podsRes, Verb: VerbGet, Name: "frontend-1"}

	denyNameFilter := RuleSpec{
		Namespaces: []string{"ns"},
		Effect:     EffectDeny,
		Capabilities: []CapabilityGrant{{
			Resource: podsRes,
			Verb:     VerbGet,
			Filter:   CapabilityFilter{Names: NameFilter{Include: []string{"frontend-*"}}},
		}},
	}
	allowPodsGet := RuleSpec{
		Namespaces:   []string{"ns"},
		Effect:       EffectAllow,
		Capabilities: []CapabilityGrant{{Resource: podsRes, Verb: VerbGet}},
	}

	cases := []struct {
		name        string
		specs       []RuleSpec
		req         Request
		wantProceed bool
		wantReason  string
	}{
		{
			name: "scope-only deny short-circuits",
			specs: []RuleSpec{
				{Namespaces: []string{"ns"}, Effect: EffectDeny},
				allowPodsGet,
			},
			req:         defaultReq,
			wantProceed: false,
			wantReason:  ReasonDenied,
		},
		{
			name:        "deny name filter matching the requested name",
			specs:       []RuleSpec{denyNameFilter, allowPodsGet},
			req:         defaultReq,
			wantProceed: false,
			wantReason:  ReasonDenied,
		},
		{
			name:        "deny name filter not matching proceeds",
			specs:       []RuleSpec{denyNameFilter, allowPodsGet},
			req:         Request{Namespace: "ns", Namespaced: true, Resource: podsRes, Verb: VerbGet, Name: "backend-1"},
			wantProceed: true,
		},
		{
			name: "deny label filter is not pre-evaluable",
			specs: []RuleSpec{
				{
					Namespaces: []string{"ns"},
					Effect:     EffectDeny,
					Capabilities: []CapabilityGrant{{
						Resource: podsRes,
						Verb:     VerbGet,
						Filter:   CapabilityFilter{Labels: LabelFilter{Require: []string{"noai"}}},
					}},
				},
				allowPodsGet,
			},
			req:         defaultReq,
			wantProceed: true,
		},
		{
			name: "deny label filter with no allow denies",
			specs: []RuleSpec{{
				Namespaces: []string{"ns"},
				Effect:     EffectDeny,
				Capabilities: []CapabilityGrant{{
					Resource: podsRes,
					Verb:     VerbGet,
					Filter:   CapabilityFilter{Labels: LabelFilter{Require: []string{"noai"}}},
				}},
			}},
			req:         defaultReq,
			wantProceed: false,
			wantReason:  ReasonNoMatchingRule,
		},
		{
			name:        "earlier allow is never shadowed by a later deny",
			specs:       []RuleSpec{allowPodsGet, denyNameFilter},
			req:         defaultReq,
			wantProceed: true,
		},
		{
			name: "deny for another resource does not pre-deny",
			specs: []RuleSpec{{
				Namespaces:   []string{"ns"},
				Effect:       EffectDeny,
				Capabilities: []CapabilityGrant{{Resource: secrets, Verb: VerbGet}},
			}},
			req:         defaultReq,
			wantProceed: false,
			wantReason:  ReasonNoMatchingRule,
		},
		{
			name: "all-namespaces list has no scope match but is granted anywhere",
			specs: []RuleSpec{{
				Namespaces:   []string{"ns"},
				Effect:       EffectAllow,
				Capabilities: []CapabilityGrant{{Resource: podsRes, Verb: VerbList}},
			}},
			req:         Request{Namespaced: true, Resource: podsRes, Verb: VerbList},
			wantProceed: true,
		},
		{
			name: "allow wildcard never covers a subresource",
			specs: []RuleSpec{{
				Namespaces:   []string{"ns"},
				Effect:       EffectAllow,
				Capabilities: []CapabilityGrant{{ResourceWildcard: true, Verb: VerbGet}},
			}},
			req:         Request{Namespace: "ns", Namespaced: true, Resource: podsLogRes, Verb: VerbGet, Name: "x"},
			wantProceed: false,
			wantReason:  ReasonNoMatchingRule,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := Build(tc.specs, nil)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			proceed, reason := compiled.PreCheck(&tc.req)
			if proceed != tc.wantProceed {
				t.Fatalf("proceed = %v (%q), want %v", proceed, reason, tc.wantProceed)
			}
			if !tc.wantProceed && tc.wantReason != "" && reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// TestPreCheckNeverGrantsWhenEvaluateDeniesAndViceVersa checks that a proceed
// decision is always consistent with a subsequent Evaluate for requests whose
// filters are fully known (get without a label filter).
func TestPreCheckAgreesWithEvaluateWhenPreEvaluable(t *testing.T) {
	podsRes := Resource{Name: "pods"}
	specs := []RuleSpec{
		{
			Namespaces: []string{"ns"},
			Effect:     EffectDeny,
			Capabilities: []CapabilityGrant{{
				Resource: podsRes,
				Verb:     VerbGet,
				Filter:   CapabilityFilter{Names: NameFilter{Include: []string{"blocked-*"}}},
			}},
		},
		{
			Namespaces:   []string{"ns"},
			Effect:       EffectAllow,
			Capabilities: []CapabilityGrant{{Resource: podsRes, Verb: VerbGet}},
		},
	}
	compiled, err := Build(specs, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for _, name := range []string{"blocked-1", "ok-1"} {
		req := Request{Namespace: "ns", Namespaced: true, Resource: podsRes, Verb: VerbGet, Name: name}
		proceed, _ := compiled.PreCheck(&req)
		decision := compiled.Evaluate(&req)
		if proceed != decision.Allowed {
			t.Fatalf("name %q: PreCheck proceed=%v but Evaluate allowed=%v", name, proceed, decision.Allowed)
		}
	}
}
