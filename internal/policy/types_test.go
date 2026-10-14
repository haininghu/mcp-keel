package policy

import (
	"slices"
	"testing"
)

func TestResourceString(t *testing.T) {
	cases := []struct {
		resource Resource
		want     string
	}{
		{Resource{Name: "pods"}, "pods"},
		{Resource{Group: "apps", Name: "deployments"}, "apps/deployments"},
		{Resource{Name: "pods", Subresource: "log"}, "pods/log"},
		{Resource{Group: "apps", Name: "deployments", Subresource: "scale"}, "apps/deployments/scale"},
		{Resource{}, ""},
	}
	for _, tc := range cases {
		if got := tc.resource.String(); got != tc.want {
			t.Errorf("Resource%+v.String() = %q, want %q", tc.resource, got, tc.want)
		}
	}
}

func TestResourceIsSubresource(t *testing.T) {
	if pods.IsSubresource() {
		t.Error("pods.IsSubresource() = true, want false")
	}
	if !podsLog.IsSubresource() {
		t.Error("pods/log.IsSubresource() = false, want true")
	}
}

func TestBuiltinSensitive(t *testing.T) {
	want := []Resource{
		{Name: "secrets"},
		{Name: "serviceaccounts"},
		{Name: "configmaps"},
		{Group: "rbac.authorization.k8s.io", Name: "roles"},
		{Group: "rbac.authorization.k8s.io", Name: "rolebindings"},
		{Group: "rbac.authorization.k8s.io", Name: "clusterroles"},
		{Group: "rbac.authorization.k8s.io", Name: "clusterrolebindings"},
	}
	if got := BuiltinSensitive(); !slices.Equal(got, want) {
		t.Errorf("BuiltinSensitive() = %v, want %v", got, want)
	}
}
