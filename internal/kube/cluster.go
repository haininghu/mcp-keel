package kube

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"

	"github.com/haininghu/mcp-keel/internal/policy"
)

// Cluster is a lazily built, cached client for one (provider, context) pair. It
// is safe for concurrent use and carries no authorization state. All discovery
// results are cached for the configured TTL.
type Cluster struct {
	provider string
	context  string

	dynamic dynamic.Interface
	source  discoverySource

	cacheTTL time.Duration
	now      func() time.Time

	mu    sync.Mutex
	cache *discoveryState
}

// Provider returns the provider name this cluster belongs to.
func (c *Cluster) Provider() string { return c.provider }

// Context returns the kubeconfig context this cluster uses.
func (c *Cluster) Context() string { return c.context }

// clock returns the cluster's notion of now, defaulting to time.Now.
func (c *Cluster) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Canonicalize resolves raw to the single canonical resource form of ADR 0012.
// A standalone "*" returns wildcard true and a zero Resource. Any other value
// that cannot be resolved unambiguously fails closed. A missing resource may be
// a just-created CRD, so the discovery cache is invalidated once and the lookup
// retried before denying; ambiguity and malformed input are not retried.
func (c *Cluster) Canonicalize(ctx context.Context, raw string) (policy.Resource, bool, error) {
	if raw == "*" {
		return policy.Resource{}, true, nil
	}
	st, err := c.state(ctx, false)
	if err != nil {
		return policy.Resource{}, false, err
	}
	res, err := resolveCanonical(st, raw)
	if err == nil {
		return res, false, nil
	}
	if c.cacheTTL > 0 && errors.Is(err, ErrUnknownResource) && !errors.Is(err, ErrPartialDiscovery) {
		if fresh, reloadErr := c.state(ctx, true); reloadErr == nil {
			if res, retryErr := resolveCanonical(fresh, raw); retryErr == nil {
				return res, false, nil
			} else {
				err = retryErr
			}
		}
	}
	return policy.Resource{}, false, err
}

// CanonicalizeAll is the ambiguity-tolerant variant of Canonicalize used to
// extend the sensitive-resource set: when a name matches more than one group it
// returns every matching canonical form instead of an ambiguity error
// (ADR 0004). An unknown or malformed identifier still fails. A standalone
// wildcard is rejected; callers never pass it here.
func (c *Cluster) CanonicalizeAll(ctx context.Context, raw string) ([]policy.Resource, error) {
	if raw == "*" {
		return nil, fmt.Errorf("%w: %q: wildcard is not allowed", ErrInvalidResource, raw)
	}
	st, err := c.state(ctx, false)
	if err != nil {
		return nil, err
	}
	return resolveCanonicalAll(st, raw)
}

// SupportsVerb reports whether res supports verb according to the API
// resource's Verbs list (for example "list" is not supported on "pods/log").
// The resource wildcard and the verb wildcard support every verb.
func (c *Cluster) SupportsVerb(ctx context.Context, res policy.Resource, verb policy.Verb) (bool, error) {
	if res.Name == "*" || verb == policy.VerbWildcard {
		return true, nil
	}
	if res.Name == "" {
		return false, nil
	}
	st, err := c.state(ctx, false)
	if err != nil {
		return false, err
	}
	for i := range st.candidates {
		cand := &st.candidates[i]
		if cand.group != res.Group || cand.resource != res.Name || cand.subresource != res.Subresource {
			continue
		}
		return slices.Contains(cand.verbs, string(verb)), nil
	}
	return false, nil
}

// Namespaced reports whether res is namespaced, from discovery. It fails closed
// when the resource cannot be resolved.
func (c *Cluster) Namespaced(ctx context.Context, res policy.Resource) (bool, error) {
	st, err := c.state(ctx, false)
	if err != nil {
		return false, err
	}
	for i := range st.candidates {
		cand := &st.candidates[i]
		if cand.group == res.Group && cand.resource == res.Name && cand.subresource == "" {
			return cand.namespaced, nil
		}
	}
	return false, fmt.Errorf("%w: %s", ErrUnknownResource, res)
}

// Get fetches a single object. namespace is required for namespaced resources
// and ignored for cluster-scoped ones; the canonical resource decides. API
// errors are mapped to sentinels and never expose a response body.
func (c *Cluster) Get(ctx context.Context, res policy.Resource, namespace, name string) (*unstructured.Unstructured, error) {
	gvr, namespaced, err := c.resolveGVR(ctx, res)
	if err != nil {
		return nil, err
	}
	var obj *unstructured.Unstructured
	if namespaced {
		obj, err = c.dynamic.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{}, subresourceArgs(res)...)
	} else {
		obj, err = c.dynamic.Resource(gvr).Get(ctx, name, metav1.GetOptions{}, subresourceArgs(res)...)
	}
	if err != nil {
		return nil, safeError(err)
	}
	return obj, nil
}

// List fetches a bounded window of objects. An empty namespace on a namespaced
// resource lists all namespaces; cluster-scoped resources are always listed
// cluster-wide. Listing a subresource is rejected (it is gated by SupportsVerb
// upstream). API errors are mapped to sentinels and never expose a body.
func (c *Cluster) List(ctx context.Context, res policy.Resource, namespace, labelSelector string, limit int) ([]unstructured.Unstructured, error) {
	if res.IsSubresource() {
		return nil, fmt.Errorf("%w: cannot list subresource %s", ErrUnsupportedVerb, res)
	}
	gvr, namespaced, err := c.resolveGVR(ctx, res)
	if err != nil {
		return nil, err
	}
	opts := metav1.ListOptions{LabelSelector: labelSelector}
	if limit > 0 {
		opts.Limit = int64(limit)
	}
	var list *unstructured.UnstructuredList
	if namespaced && namespace != "" {
		list, err = c.dynamic.Resource(gvr).Namespace(namespace).List(ctx, opts)
	} else {
		list, err = c.dynamic.Resource(gvr).List(ctx, opts)
	}
	if err != nil {
		return nil, safeError(err)
	}
	return list.Items, nil
}

// NamespaceMarked reports whether the namespace carries the given label. It
// backs the optional namespace-marker overlay; any API error fails closed.
func (c *Cluster) NamespaceMarked(ctx context.Context, namespace, label string) (bool, error) {
	if namespace == "" {
		return false, fmt.Errorf("kube: namespace must not be empty")
	}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	obj, err := c.dynamic.Resource(gvr).Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return false, safeError(err)
	}
	_, marked := obj.GetLabels()[label]
	return marked, nil
}

// resolveGVR resolves a canonical resource to its preferred-version GVR and
// reports whether it is namespaced. It fails closed when the base resource is
// absent from discovery.
func (c *Cluster) resolveGVR(ctx context.Context, res policy.Resource) (schema.GroupVersionResource, bool, error) {
	st, err := c.state(ctx, false)
	if err != nil {
		return schema.GroupVersionResource{}, false, err
	}
	var namespaced bool
	found := false
	for i := range st.candidates {
		cand := &st.candidates[i]
		if cand.subresource == "" && cand.group == res.Group && cand.resource == res.Name {
			namespaced = cand.namespaced
			found = true
			break
		}
	}
	if !found {
		return schema.GroupVersionResource{}, false, fmt.Errorf("%w: %s", ErrUnknownResource, res)
	}
	gvr, err := st.mapper.ResourceFor(schema.GroupVersionResource{Group: res.Group, Resource: res.Name})
	if err != nil {
		return schema.GroupVersionResource{}, false, fmt.Errorf("%w: %s", ErrUnknownResource, res)
	}
	return gvr, namespaced, nil
}

// subresourceArgs returns the dynamic client subresource path segments for res.
func subresourceArgs(res policy.Resource) []string {
	if res.Subresource == "" {
		return nil
	}
	return []string{res.Subresource}
}

// discoveryClientSource adapts a client-go discovery client to discoverySource
// and makes partial group failures non-fatal (ADR 0014). Failed groups are
// logged server-side without any response body.
//
// It uses ServerGroupsAndResources rather than ServerPreferredResources because
// the latter filters out subresource entries ("pods/log"), which ADR 0012
// requires for canonicalisation. The returned groups carry the preferred
// version, so the RESTMapper still resolves the preferred GVR.
type discoveryClientSource struct {
	client discovery.DiscoveryInterfaceWithContext
	logger *slog.Logger
}

func (s discoveryClientSource) resources(ctx context.Context) ([]*metav1.APIGroup, []*metav1.APIResourceList, bool, error) {
	groups, lists, err := discovery.ServerGroupsAndResourcesWithContext(ctx, s.client)
	if err != nil {
		if discovery.IsGroupDiscoveryFailedError(err) {
			failed, _ := discovery.GroupDiscoveryFailedErrorGroups(err)
			for gv, groupErr := range failed {
				s.logger.Warn("discovery group failed; using partial results",
					"groupVersion", gv.String(), "status", apiStatusCode(groupErr))
			}
			return groups, lists, true, nil
		}
		return nil, nil, false, safeError(err)
	}
	return groups, lists, false, nil
}
