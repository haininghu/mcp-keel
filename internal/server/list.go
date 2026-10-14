package server

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/hvo/mcp-keel/internal/policy"
)

// handleList implements the list tool: resolve, canonicalise, validate scope,
// pre-check, fetch a bounded window, evaluate every item and shape the
// response. A denied list is an empty result, never an error (ADR 0008).
func (s *Server) handleList(ctx context.Context, _ *mcp.CallToolRequest, in listInput) (*mcp.CallToolResult, any, error) {
	cluster, err := s.resolveRegistry(in.Provider, in.Context)
	if err != nil {
		return nil, nil, err
	}

	res, err := canonicalizeResolve(ctx, cluster, in.Resource)
	if err != nil {
		return nil, nil, err
	}

	namespaced, err := cluster.Namespaced(ctx, res)
	if err != nil {
		return nil, nil, resourceInspectionError(in.Resource, err)
	}
	if namespaced {
		if in.Namespace != "" {
			if err := validateNamespace(in.Namespace); err != nil {
				return nil, nil, err
			}
		}
	} else if in.Namespace != "" {
		return nil, nil, errors.New("namespace is not allowed for a cluster-scoped resource")
	}

	supported, err := cluster.SupportsVerb(ctx, res, policy.VerbList)
	if err != nil {
		return nil, nil, resourceInspectionError(in.Resource, err)
	}
	if !supported {
		return nil, nil, errors.New("unknown resource: does not support list")
	}
	if err := validateLabelSelector(in.LabelSelector); err != nil {
		return nil, nil, err
	}

	limit := s.clampListLimit(in.Limit)
	compiled, err := s.policyFor(ctx, in.Provider, in.Context, cluster)
	if err != nil {
		return nil, nil, err
	}
	proceed, reason := compiled.PreCheck(policy.Request{
		Namespace:  in.Namespace,
		Namespaced: namespaced,
		Resource:   res,
		Verb:       policy.VerbList,
	})
	if !proceed {
		s.logger.Info("list denied by pre-check",
			"provider", in.Provider, "context", in.Context,
			"resource", res.String(), "namespace", in.Namespace, "reason", reason)
		return jsonResult(s.emptyListOutput(in, res))
	}

	items, err := cluster.List(ctx, res, in.Namespace, in.LabelSelector, limit+1)
	if err != nil {
		return nil, nil, mapKubeError(err)
	}

	out := s.shapeList(ctx, cluster, compiled, in, res, namespaced, items, limit)
	return jsonResult(out)
}

// emptyListOutput builds the denied-list envelope: no items, not truncated.
func (s *Server) emptyListOutput(in listInput, res policy.Resource) listOutput {
	return listOutput{
		Provider:  in.Provider,
		Context:   in.Context,
		Resource:  res.String(),
		Namespace: in.Namespace,
		Items:     []any{},
		Truncated: false,
	}
}

// shapeList evaluates each fetched item, drops denied or marker-protected
// items, applies the object-size and response-budget limits, and returns the
// list envelope. The number of hidden items is logged server-side only.
func (s *Server) shapeList(ctx context.Context, cluster Cluster, compiled *policy.Policy, in listInput, res policy.Resource, namespaced bool, items []unstructured.Unstructured, limit int) listOutput {
	out := s.emptyListOutput(in, res)
	windowTruncated := len(items) > limit

	// Response budget: the fixed envelope overhead plus the running item bytes.
	overhead := marshalSize(listOutput{
		Provider: in.Provider, Context: in.Context, Resource: res.String(),
		Namespace: in.Namespace, Items: []any{}, Truncated: false,
	})
	maxResponse := s.cfg.Server.MaxResponseBytes
	itemBytes := 0

	markerCache := make(map[string]bool, 4)
	var hidden, returned int

	for i := range items {
		item := &items[i]
		decision := compiled.Evaluate(policy.Request{
			Namespace:  item.GetNamespace(),
			Namespaced: namespaced,
			Resource:   res,
			Verb:       policy.VerbList,
			Name:       item.GetName(),
			Labels:     policy.LabelSet{Known: true, Values: item.GetLabels()},
		})
		if !decision.Allowed {
			hidden++
			continue
		}
		if namespaced && s.markerEnabled() && !decision.NamespaceMarkerExempt {
			namespace := item.GetNamespace()
			marked, ok := markerCache[namespace]
			if !ok {
				var markerErr error
				marked, markerErr = cluster.NamespaceMarked(ctx, namespace, s.markerLabel())
				if markerErr != nil {
					s.logger.Error("namespace marker check failed; hiding item",
						"provider", in.Provider, "context", in.Context,
						"namespace", namespace, "error", markerErr.Error())
					marked = true
				}
				markerCache[namespace] = marked
			}
			if marked {
				hidden++
				continue
			}
		}
		if returned >= limit {
			windowTruncated = true
			continue
		}

		object, reduced := s.fitObject(item)
		if reduced {
			out.Truncated = true
		}
		encoded, marshalErr := json.Marshal(object)
		if marshalErr != nil {
			out.Truncated = true
			continue
		}
		extra := len(encoded)
		if returned > 0 {
			extra++
		}
		if overhead+itemBytes+extra > maxResponse {
			out.Truncated = true
			break
		}
		itemBytes += extra
		out.Items = append(out.Items, object)
		returned++
	}

	out.Truncated = out.Truncated || windowTruncated
	s.logger.Info("list completed",
		"provider", in.Provider, "context", in.Context, "resource", res.String(),
		"namespace", in.Namespace, "returned", returned, "hidden", hidden, "truncated", out.Truncated)
	return out
}
