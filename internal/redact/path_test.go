package redact

import (
	"reflect"
	"testing"
)

func TestParsePath(t *testing.T) {
	cases := []struct {
		name string
		path string
		want []pathStep
	}{
		{
			name: "bare key",
			path: "data",
			want: []pathStep{{kind: stepKey, key: "data"}},
		},
		{
			name: "nested keys",
			path: "spec.containers",
			want: []pathStep{{kind: stepKey, key: "spec"}, {kind: stepKey, key: "containers"}},
		},
		{
			name: "quoted key with dot and slash",
			path: `metadata.annotations["a.b/c"]`,
			want: []pathStep{
				{kind: stepKey, key: "metadata"},
				{kind: stepKey, key: "annotations"},
				{kind: stepKey, key: "a.b/c"},
			},
		},
		{
			name: "wildcard segment",
			path: "spec.containers[*].env",
			want: []pathStep{
				{kind: stepKey, key: "spec"},
				{kind: stepKey, key: "containers"},
				{kind: stepWildcard},
				{kind: stepKey, key: "env"},
			},
		},
		{
			name: "index segment",
			path: "items[2].value",
			want: []pathStep{
				{kind: stepKey, key: "items"},
				{kind: stepIndex, index: 2},
				{kind: stepKey, key: "value"},
			},
		},
		{
			name: "predicate segment",
			path: "spec.containers[name=web].env",
			want: []pathStep{
				{kind: stepKey, key: "spec"},
				{kind: stepKey, key: "containers"},
				{kind: stepPredicate, field: "name", value: "web"},
				{kind: stepKey, key: "env"},
			},
		},
		{
			name: "predicate value keeps equals",
			path: "items[key=a=b]",
			want: []pathStep{
				{kind: stepKey, key: "items"},
				{kind: stepPredicate, field: "key", value: "a=b"},
			},
		},
		{
			name: "predicate empty value",
			path: "items[key=]",
			want: []pathStep{
				{kind: stepKey, key: "items"},
				{kind: stepPredicate, field: "key", value: ""},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePath(tc.path)
			if err != nil {
				t.Fatalf("parsePath(%q) error = %v", tc.path, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parsePath(%q) = %+v, want %+v", tc.path, got, tc.want)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	valid := []string{
		"a",
		"a.b",
		`a["b.c"]`,
		"a[*]",
		"a[0]",
		"a[name=x]",
		"a[name=x=y]",
		`a[*].b[name=c].d`,
		`metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]`,
	}
	for _, path := range valid {
		t.Run("valid "+path, func(t *testing.T) {
			if err := ValidatePath(path); err != nil {
				t.Fatalf("ValidatePath(%q) error = %v", path, err)
			}
		})
	}

	invalid := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"leading dot", ".a"},
		{"trailing dot", "a."},
		{"double dot", "a..b"},
		{"unterminated bracket", "a["},
		{"empty bracket", "a[]"},
		{"unterminated wildcard", "a[*"},
		{"invalid wildcard", "a[**]"},
		{"unterminated quoted key", `a["b`},
		{"quote inside quoted key", `a["b"c"]`},
		{"invalid selector", "a[b]"},
		{"empty predicate field", "a[=x]"},
		{"closing bracket in predicate value", "a[name=x]y]"},
		{"key after bracket without dot", "a[0]b"},
		{"closing bracket in bare key", "a]b"},
		{"quote in bare key", `a"b`},
		{"index out of range", "a[999999999999999999999]"},
	}
	for _, tc := range invalid {
		t.Run("invalid "+tc.name, func(t *testing.T) {
			if err := ValidatePath(tc.path); err == nil {
				t.Fatalf("ValidatePath(%q) error = nil, want an error", tc.path)
			}
		})
	}
}
