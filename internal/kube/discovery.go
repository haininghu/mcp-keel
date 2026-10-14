package kube

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/restmapper"
)

// discoverySource loads the API groups and resources of one cluster. It is an
// interface so canonicalisation can be tested without a cluster.
type discoverySource interface {
	// resources returns the API groups and the full resource lists (including
	// subresource entries) and reports whether discovery was partial. Partial
	// results are still returned; the caller fails closed on unqualified names.
	resources(ctx context.Context) ([]*metav1.APIGroup, []*metav1.APIResourceList, bool, error)
}

// discoveryState is one cached snapshot of a cluster's discovery. It holds no
// authorization state.
type discoveryState struct {
	candidates []candidate
	mapper     meta.RESTMapper
	partial    bool
	loadedAt   time.Time
}

// load reads discovery and flattens it. It never returns a raw client-go error.
func (c *Cluster) load(ctx context.Context) (*discoveryState, error) {
	groups, lists, partial, err := c.source.resources(ctx)
	if err != nil {
		return nil, err
	}
	return &discoveryState{
		candidates: buildCandidates(lists),
		mapper:     buildRESTMapper(groups, lists),
		partial:    partial,
		loadedAt:   c.clock(),
	}, nil
}

// state returns the cached discovery state, loading it when the cache is cold
// or expired (or when force is set). discovery_cache_ttl == 0 disables caching
// and reloads on every call.
func (c *Cluster) state(ctx context.Context, force bool) (*discoveryState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.cache != nil && c.cacheTTL > 0 && c.clock().Sub(c.cache.loadedAt) < c.cacheTTL {
		return c.cache, nil
	}
	st, err := c.load(ctx)
	if err != nil {
		return nil, err
	}
	c.cache = st
	return st, nil
}

// buildRESTMapper builds a RESTMapper from the discovered groups and resource
// lists. The mapper resolves the preferred version for the API call; it does
// not represent subresources, which the caller appends to the base GVR.
func buildRESTMapper(groups []*metav1.APIGroup, lists []*metav1.APIResourceList) meta.RESTMapper {
	byGroup := make(map[string]*restmapper.APIGroupResources)
	var order []string
	for _, group := range groups {
		if group == nil {
			continue
		}
		if _, ok := byGroup[group.Name]; ok {
			continue
		}
		byGroup[group.Name] = &restmapper.APIGroupResources{
			Group:              *group,
			VersionedResources: make(map[string][]metav1.APIResource),
		}
		order = append(order, group.Name)
	}
	for _, list := range lists {
		if list == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			continue
		}
		group, ok := byGroup[gv.Group]
		if !ok {
			group = &restmapper.APIGroupResources{
				Group:              metav1.APIGroup{Name: gv.Group},
				VersionedResources: make(map[string][]metav1.APIResource),
			}
			byGroup[gv.Group] = group
			order = append(order, gv.Group)
		}
		group.VersionedResources[gv.Version] = list.APIResources
	}
	apiGroupResources := make([]*restmapper.APIGroupResources, 0, len(order))
	for _, name := range order {
		apiGroupResources = append(apiGroupResources, byGroup[name])
	}
	return restmapper.NewDiscoveryRESTMapper(apiGroupResources)
}
