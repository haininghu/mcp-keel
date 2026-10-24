package kube

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/haininghu/mcp-keel/internal/policy"
)

// fakeSource is a discoverySource backed by static resource lists.
type fakeSource struct {
	groups  []*metav1.APIGroup
	lists   []*metav1.APIResourceList
	partial bool
	err     error
}

func (f fakeSource) resources(context.Context) ([]*metav1.APIGroup, []*metav1.APIResourceList, bool, error) {
	return f.groups, f.lists, f.partial, f.err
}

// testCluster builds a cluster over static discovery, without a real client.
func testCluster(lists []*metav1.APIResourceList, partial bool) *Cluster {
	return &Cluster{
		source:   fakeSource{lists: lists, partial: partial},
		cacheTTL: time.Minute,
		now:      time.Now,
	}
}

func coreV1List() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "pods", SingularName: "pod", Namespaced: true, Kind: "Pod", ShortNames: []string{"po"}, Verbs: metav1.Verbs{"get", "list"}},
			{Name: "pods/log", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get"}},
			{Name: "events", SingularName: "event", Namespaced: true, Kind: "Event", ShortNames: []string{"ev"}, Verbs: metav1.Verbs{"get", "list"}},
			{Name: "namespaces", SingularName: "namespace", Namespaced: false, Kind: "Namespace", ShortNames: []string{"ns"}, Verbs: metav1.Verbs{"get", "list"}},
		},
	}
}

func appsV1List() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: "apps/v1",
		APIResources: []metav1.APIResource{
			{Name: "deployments", SingularName: "deployment", Namespaced: true, Kind: "Deployment", ShortNames: []string{"deploy"}, Verbs: metav1.Verbs{"get", "list"}},
			{Name: "deployments/scale", Namespaced: true, Kind: "Scale", Verbs: metav1.Verbs{"get"}},
		},
	}
}

func eventsV1List() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: "events.k8s.io/v1",
		APIResources: []metav1.APIResource{
			{Name: "events", SingularName: "event", Namespaced: true, Kind: "Event", Verbs: metav1.Verbs{"get", "list"}},
		},
	}
}

func standardLists() []*metav1.APIResourceList {
	return []*metav1.APIResourceList{coreV1List(), appsV1List(), eventsV1List()}
}

func TestCanonicalize(t *testing.T) {
	cluster := testCluster(standardLists(), false)
	tests := []struct {
		name         string
		raw          string
		want         policy.Resource
		wantWildcard bool
		wantErr      error
	}{
		{name: "plural", raw: "pods", want: policy.Resource{Name: "pods"}},
		{name: "shortname", raw: "po", want: policy.Resource{Name: "pods"}},
		{name: "singular", raw: "pod", want: policy.Resource{Name: "pods"}},
		{name: "kind case-insensitive", raw: "Pod", want: policy.Resource{Name: "pods"}},
		{name: "shortname group", raw: "deploy", want: policy.Resource{Group: "apps", Name: "deployments"}},
		{name: "kind group", raw: "Deployment", want: policy.Resource{Group: "apps", Name: "deployments"}},
		{name: "explicit group", raw: "apps/deployments", want: policy.Resource{Group: "apps", Name: "deployments"}},
		{name: "core alias", raw: "core/pods", want: policy.Resource{Name: "pods"}},
		{name: "core alias events", raw: "core/events", want: policy.Resource{Name: "events"}},
		{name: "subresource", raw: "pods/log", want: policy.Resource{Name: "pods", Subresource: "log"}},
		{name: "group subresource", raw: "apps/deployments/scale", want: policy.Resource{Group: "apps", Name: "deployments", Subresource: "scale"}},
		{name: "qualified events", raw: "events.k8s.io/events", want: policy.Resource{Group: "events.k8s.io", Name: "events"}},
		{name: "cluster-scoped", raw: "namespaces", want: policy.Resource{Name: "namespaces"}},
		{name: "ambiguous events", raw: "events", wantErr: ErrAmbiguousResource},
		{name: "wildcard", raw: "*", wantWildcard: true},
		{name: "wildcard group rejected", raw: "apps/*", wantErr: ErrInvalidResource},
		{name: "wildcard subresource rejected", raw: "*/log", wantErr: ErrInvalidResource},
		{name: "unknown resource", raw: "widgets", wantErr: ErrUnknownResource},
		{name: "too many segments", raw: "a/b/c/d", wantErr: ErrInvalidResource},
		{name: "empty segment", raw: "apps//scale", wantErr: ErrInvalidResource},
		{name: "unknown group", raw: "example.com/widgets", wantErr: ErrUnknownResource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, wildcard, err := cluster.Canonicalize(context.Background(), tt.raw)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Canonicalize(%q) error = %v, want %v", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Canonicalize(%q) unexpected error: %v", tt.raw, err)
			}
			if wildcard != tt.wantWildcard {
				t.Fatalf("Canonicalize(%q) wildcard = %v, want %v", tt.raw, wildcard, tt.wantWildcard)
			}
			if got != tt.want {
				t.Fatalf("Canonicalize(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCanonicalizePartialDiscovery(t *testing.T) {
	cluster := testCluster([]*metav1.APIResourceList{coreV1List(), appsV1List()}, true)
	ctx := context.Background()

	// Unqualified names are denied while discovery is partial.
	if _, _, err := cluster.Canonicalize(ctx, "pods"); !errors.Is(err, ErrUnknownResource) || !errors.Is(err, ErrPartialDiscovery) {
		t.Fatalf("unqualified name while partial: error = %v, want unknown+partial", err)
	}
	if _, _, err := cluster.Canonicalize(ctx, "pods/log"); !errors.Is(err, ErrPartialDiscovery) {
		t.Fatalf("resource/subresource while partial: error = %v, want partial", err)
	}
	// Qualified names still resolve.
	res, _, err := cluster.Canonicalize(ctx, "core/pods")
	if err != nil || res != (policy.Resource{Name: "pods"}) {
		t.Fatalf("core/pods while partial = %v, %v", res, err)
	}
	res, _, err = cluster.Canonicalize(ctx, "apps/deployments")
	if err != nil || res != (policy.Resource{Group: "apps", Name: "deployments"}) {
		t.Fatalf("apps/deployments while partial = %v, %v", res, err)
	}
	// An unknown qualified group is denied.
	if _, _, err := cluster.Canonicalize(ctx, "example.com/widgets"); !errors.Is(err, ErrPartialDiscovery) {
		t.Fatalf("unknown group while partial: error = %v, want partial", err)
	}
}

func TestSupportsVerb(t *testing.T) {
	cluster := testCluster(standardLists(), false)
	ctx := context.Background()

	ok, err := cluster.SupportsVerb(ctx, policy.Resource{Name: "pods"}, policy.VerbList)
	if err != nil || !ok {
		t.Fatalf("list pods = %v, %v, want true", ok, err)
	}
	ok, err = cluster.SupportsVerb(ctx, policy.Resource{Name: "pods", Subresource: "log"}, policy.VerbList)
	if err != nil || ok {
		t.Fatalf("list pods/log = %v, %v, want false", ok, err)
	}
	ok, err = cluster.SupportsVerb(ctx, policy.Resource{Name: "pods", Subresource: "log"}, policy.VerbGet)
	if err != nil || !ok {
		t.Fatalf("get pods/log = %v, %v, want true", ok, err)
	}
	ok, err = cluster.SupportsVerb(ctx, policy.Resource{Name: "*"}, policy.VerbList)
	if err != nil || !ok {
		t.Fatalf("list wildcard = %v, %v, want true", ok, err)
	}
	ok, err = cluster.SupportsVerb(ctx, policy.Resource{Name: "widgets"}, policy.VerbGet)
	if err != nil || ok {
		t.Fatalf("get unknown = %v, %v, want false", ok, err)
	}
}

func TestNamespaced(t *testing.T) {
	cluster := testCluster(standardLists(), false)
	ctx := context.Background()

	ok, err := cluster.Namespaced(ctx, policy.Resource{Name: "pods"})
	if err != nil || !ok {
		t.Fatalf("pods namespaced = %v, %v, want true", ok, err)
	}
	ok, err = cluster.Namespaced(ctx, policy.Resource{Name: "namespaces"})
	if err != nil || ok {
		t.Fatalf("namespaces namespaced = %v, %v, want false", ok, err)
	}
	if _, err := cluster.Namespaced(ctx, policy.Resource{Name: "widgets"}); !errors.Is(err, ErrUnknownResource) {
		t.Fatalf("unknown namespaced error = %v, want unknown resource", err)
	}
}

func TestCanonicalizeCacheRetryOnUnknown(t *testing.T) {
	source := &countingSource{lists: []*metav1.APIResourceList{coreV1List()}}
	cluster := &Cluster{
		source:   source,
		cacheTTL: time.Minute,
		now:      time.Now,
	}
	ctx := context.Background()
	if _, _, err := cluster.Canonicalize(ctx, "pods"); err != nil {
		t.Fatalf("pods: %v", err)
	}
	if source.calls != 1 {
		t.Fatalf("expected one discovery load, got %d", source.calls)
	}
	if _, _, err := cluster.Canonicalize(ctx, "widgets"); !errors.Is(err, ErrUnknownResource) {
		t.Fatalf("widgets error = %v, want unknown", err)
	}
	// The cache is invalidated once and reloaded on an unknown resource.
	if source.calls != 2 {
		t.Fatalf("expected a single cache invalidation, got %d loads", source.calls)
	}
}

// countingSource counts how often discovery is loaded.
type countingSource struct {
	lists []*metav1.APIResourceList
	calls int
}

func (s *countingSource) resources(context.Context) ([]*metav1.APIGroup, []*metav1.APIResourceList, bool, error) {
	s.calls++
	return nil, s.lists, false, nil
}

func TestCanonicalizeAll(t *testing.T) {
	cluster := testCluster(standardLists(), false)
	ctx := context.Background()

	got, err := cluster.CanonicalizeAll(ctx, "events")
	if err != nil {
		t.Fatalf("CanonicalizeAll(events) error: %v", err)
	}
	want := []policy.Resource{{Name: "events"}, {Group: "events.k8s.io", Name: "events"}}
	if len(got) != len(want) {
		t.Fatalf("CanonicalizeAll(events) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CanonicalizeAll(events)[%d] = %v, want %v", i, got[i], want[i])
		}
	}

	single, err := cluster.CanonicalizeAll(ctx, "apps/deployments")
	if err != nil {
		t.Fatalf("CanonicalizeAll(apps/deployments) error: %v", err)
	}
	if len(single) != 1 || single[0] != (policy.Resource{Group: "apps", Name: "deployments"}) {
		t.Fatalf("CanonicalizeAll(apps/deployments) = %v", single)
	}

	if _, err := cluster.CanonicalizeAll(ctx, "widgets"); !errors.Is(err, ErrUnknownResource) {
		t.Fatalf("CanonicalizeAll(widgets) error = %v, want unknown resource", err)
	}
	if _, err := cluster.CanonicalizeAll(ctx, "*"); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("CanonicalizeAll(*) error = %v, want invalid resource", err)
	}
}
