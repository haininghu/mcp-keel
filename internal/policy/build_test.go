package policy

import "testing"

func TestBuildValid(t *testing.T) {
	specs := []RuleSpec{
		{
			Namespaces: []string{"test-*", ""}, Effect: EffectDeny,
			Capabilities: []CapabilityGrant{{
				ResourceWildcard: true, VerbWildcard: true,
				Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"noai"}}},
			}},
		},
		{
			Namespaces: []string{"test-*"}, Effect: EffectAllow,
			Capabilities: []CapabilityGrant{
				grant(pods, VerbGet),
				{Resource: Resource{Name: "*"}, Verb: VerbList},
			},
		},
		{
			Namespaces: []string{""}, Effect: EffectAllow,
			Capabilities: []CapabilityGrant{{
				Resource: nodes, Verb: VerbList,
				Filter: CapabilityFilter{Names: NameFilter{Include: []string{"worker-*"}}},
			}},
		},
		{Namespaces: []string{"locked"}, Effect: EffectDeny},
	}
	if _, err := Build(specs, defaultSensitive()); err != nil {
		t.Fatalf("Build() error = %v", err)
	}
}

func TestBuildInvalid(t *testing.T) {
	cases := []struct {
		name string
		spec RuleSpec
	}{
		{
			name: "unknown effect",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: Effect("audit"), Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
		},
		{
			name: "empty namespaces",
			spec: RuleSpec{Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
		},
		{
			name: "invalid namespace glob",
			spec: RuleSpec{Namespaces: []string{"[bad"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{grant(pods, VerbGet)}},
		},
		{
			name: "allow rule without capabilities",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow},
		},
		{
			name: "wildcard verb on allow rule",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: pods, VerbWildcard: true}}},
		},
		{
			name: "unknown verb",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: pods, Verb: Verb("watch")}}},
		},
		{
			name: "empty resource",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Verb: VerbGet}}},
		},
		{
			name: "wildcard resource that also names a resource",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectDeny, Capabilities: []CapabilityGrant{{Resource: deployments, ResourceWildcard: true, Verb: VerbGet}}},
		},
		{
			name: "wildcard resource with a group",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: Resource{Group: "apps", Name: "*"}, Verb: VerbGet}}},
		},
		{
			name: "wildcard resource with a subresource",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: Resource{Name: "*", Subresource: "log"}, Verb: VerbGet}}},
		},
		{
			name: "invalid names.include glob",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Names: NameFilter{Include: []string{"["}}}}}},
		},
		{
			name: "invalid names.exclude glob",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Names: NameFilter{Exclude: []string{"["}}}}}},
		},
		{
			name: "label both required and excluded",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{"noai"}, Exclude: []string{"noai"}}}}}},
		},
		{
			name: "empty label entry",
			spec: RuleSpec{Namespaces: []string{"*"}, Effect: EffectAllow, Capabilities: []CapabilityGrant{{Resource: pods, Verb: VerbGet, Filter: CapabilityFilter{Labels: LabelFilter{Require: []string{""}}}}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build([]RuleSpec{tc.spec}, nil); err == nil {
				t.Fatal("Build() error = nil, want an error")
			}
		})
	}
}

func TestBuildInvalidSensitive(t *testing.T) {
	cases := []struct {
		name string
		res  Resource
	}{
		{name: "empty sensitive resource", res: Resource{}},
		{name: "wildcard sensitive resource", res: Resource{Name: "*"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build(nil, []Resource{tc.res}); err == nil {
				t.Fatal("Build() error = nil, want an error")
			}
		})
	}
}
