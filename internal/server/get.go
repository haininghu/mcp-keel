package server

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hvo/mcp-keel/internal/policy"
)

// handleGet implements the get tool: resolve, canonicalise, validate scope,
// pre-check, fetch, evaluate, apply the namespace marker, then shape output.
// Any denial is reported as "not found" (ADR 0008).
//
//nolint:gocritic // hugeParam: MCP SDK handler signature
func (s *Server) handleGet(ctx context.Context, _ *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, any, error) {
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
		if in.Namespace == "" {
			return nil, nil, errors.New("namespace is required for a namespaced resource")
		}
		if err = validateNamespace(in.Namespace); err != nil {
			return nil, nil, err
		}
	} else if in.Namespace != "" {
		return nil, nil, errors.New("namespace is not allowed for a cluster-scoped resource")
	}
	if err = validateName(in.Name); err != nil {
		return nil, nil, err
	}

	supported, err := cluster.SupportsVerb(ctx, res, policy.VerbGet)
	if err != nil {
		return nil, nil, resourceInspectionError(in.Resource, err)
	}
	if !supported {
		return nil, nil, errors.New("unknown resource: does not support get")
	}

	compiled, err := s.policyFor(ctx, in.Provider, in.Context, cluster)
	if err != nil {
		return nil, nil, err
	}
	proceed, reason := compiled.PreCheck(&policy.Request{
		Namespace:  in.Namespace,
		Namespaced: namespaced,
		Resource:   res,
		Verb:       policy.VerbGet,
		Name:       in.Name,
	})
	if !proceed {
		s.logger.Info("get denied by pre-check",
			"provider", in.Provider, "context", in.Context, "resource", res.String(),
			"namespace", in.Namespace, "name", in.Name, "reason", reason)
		return nil, nil, errNotFound
	}

	obj, err := cluster.Get(ctx, res, in.Namespace, in.Name)
	if err != nil {
		return nil, nil, mapKubeError(err)
	}
	if obj == nil {
		return nil, nil, errNotFound
	}

	decision := compiled.Evaluate(&policy.Request{
		Namespace:  in.Namespace,
		Namespaced: namespaced,
		Resource:   res,
		Verb:       policy.VerbGet,
		Name:       in.Name,
		Labels:     policy.LabelSet{Known: true, Values: obj.GetLabels()},
	})
	if !decision.Allowed {
		s.logger.Info("get denied",
			"provider", in.Provider, "context", in.Context, "resource", res.String(),
			"namespace", in.Namespace, "name", in.Name, "reason", decision.Reason)
		return nil, nil, errNotFound
	}

	if namespaced && s.markerEnabled() && !decision.NamespaceMarkerExempt {
		marked, markerErr := cluster.NamespaceMarked(ctx, in.Namespace, s.markerLabel())
		if markerErr != nil {
			s.logger.Error("namespace marker check failed; denying",
				"provider", in.Provider, "context", in.Context,
				"namespace", in.Namespace, "error", markerErr.Error())
			return nil, nil, errNotFound
		}
		if marked {
			s.logger.Info("get denied by namespace marker",
				"provider", in.Provider, "context", in.Context,
				"namespace", in.Namespace, "name", in.Name)
			return nil, nil, errNotFound
		}
	}

	return jsonResult(s.shapeGet(in.Provider, in.Context, res, in.Namespace, in.Name, obj))
}
