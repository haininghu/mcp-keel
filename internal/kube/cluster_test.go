package kube

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/hvo/mcp-keel/internal/policy"
)

func coreGroups() []*metav1.APIGroup {
	gv := metav1.GroupVersionForDiscovery{GroupVersion: "v1", Version: "v1"}
	return []*metav1.APIGroup{{
		Name:             "",
		Versions:         []metav1.GroupVersionForDiscovery{gv},
		PreferredVersion: gv,
	}}
}

func testPod() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "p1",
			"namespace": "default",
			"labels":    map[string]any{"app": "web"},
		},
	}}
}

func testNamespace() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   "protected",
			"labels": map[string]any{"mcp-keel.io/noai": "true"},
		},
	}}
}

func dynamicCluster(t *testing.T) *Cluster {
	t.Helper()
	podGVR := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{podGVR: "PodList"},
		testPod(),
		testNamespace(),
	)
	return &Cluster{
		dynamic:  client,
		source:   fakeSource{groups: coreGroups(), lists: []*metav1.APIResourceList{coreV1List()}},
		cacheTTL: time.Minute,
		now:      time.Now,
	}
}

func TestClusterList(t *testing.T) {
	cluster := dynamicCluster(t)
	ctx := context.Background()

	items, err := cluster.List(ctx, policy.Resource{Name: "pods"}, "default", "", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 1 || items[0].GetName() != "p1" {
		t.Fatalf("List items = %v", items)
	}

	items, err = cluster.List(ctx, policy.Resource{Name: "pods"}, "", "", 10)
	if err != nil {
		t.Fatalf("List all namespaces: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("List all namespaces items = %v", items)
	}
}

func TestClusterGet(t *testing.T) {
	cluster := dynamicCluster(t)
	ctx := context.Background()

	obj, err := cluster.Get(ctx, policy.Resource{Name: "pods"}, "default", "p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if obj.GetName() != "p1" {
		t.Fatalf("Get name = %s", obj.GetName())
	}

	if _, err := cluster.Get(ctx, policy.Resource{Name: "pods"}, "default", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing error = %v, want not found", err)
	}
}

func TestClusterListSubresourceRejected(t *testing.T) {
	cluster := dynamicCluster(t)
	if _, err := cluster.List(context.Background(), policy.Resource{Name: "pods", Subresource: "log"}, "default", "", 0); !errors.Is(err, ErrUnsupportedVerb) {
		t.Fatalf("List subresource error = %v, want unsupported verb", err)
	}
}

func TestClusterNamespaceMarked(t *testing.T) {
	cluster := dynamicCluster(t)
	ctx := context.Background()

	marked, err := cluster.NamespaceMarked(ctx, "protected", "mcp-keel.io/noai")
	if err != nil {
		t.Fatalf("NamespaceMarked: %v", err)
	}
	if !marked {
		t.Fatal("expected the namespace to be marked")
	}
	marked, err = cluster.NamespaceMarked(ctx, "protected", "absent")
	if err != nil || marked {
		t.Fatalf("NamespaceMarked absent = %v, %v, want false", marked, err)
	}
	if _, err := cluster.NamespaceMarked(ctx, "", "mcp-keel.io/noai"); err == nil {
		t.Fatal("expected an error for an empty namespace")
	}
	if _, err := cluster.NamespaceMarked(ctx, "missing", "mcp-keel.io/noai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("NamespaceMarked missing error = %v, want not found", err)
	}
}
