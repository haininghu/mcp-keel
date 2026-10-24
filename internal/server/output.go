package server

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/haininghu/mcp-keel/internal/policy"
)

// maxJSONSize is used when a value cannot be marshaled; it forces reduction.
const maxJSONSize = 1 << 62

// getOutput is the get response envelope (ADR 0013 / method-specs/output.md).
type getOutput struct {
	Provider  string `json:"provider"`
	Context   string `json:"context"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Object    any    `json:"object"`
	Truncated bool   `json:"truncated"`
}

// listOutput is the list response envelope (ADR 0013 / method-specs/output.md).
type listOutput struct {
	Provider  string `json:"provider"`
	Context   string `json:"context"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace"`
	Items     []any  `json:"items"`
	Truncated bool   `json:"truncated"`
}

// pruneObject returns a shallow copy of the object with
// metadata.managedFields removed. It never mutates the fetched object.
func pruneObject(obj *unstructured.Unstructured) map[string]any {
	out := make(map[string]any, len(obj.Object))
	for key, value := range obj.Object {
		out[key] = value
	}
	meta, ok := out["metadata"].(map[string]any)
	if !ok {
		return out
	}
	if _, hasManagedFields := meta["managedFields"]; !hasManagedFields {
		return out
	}
	trimmed := make(map[string]any, len(meta))
	for key, value := range meta {
		if key == "managedFields" {
			continue
		}
		trimmed[key] = value
	}
	out["metadata"] = trimmed
	return out
}

// objectSkeleton reduces an object to {apiVersion, kind, metadata}.
func objectSkeleton(obj map[string]any) map[string]any {
	out := make(map[string]any, 3)
	copyKey(out, obj, "apiVersion")
	copyKey(out, obj, "kind")
	if meta, ok := obj["metadata"].(map[string]any); ok {
		out["metadata"] = meta
	}
	return out
}

// objectMinimal reduces an object to {apiVersion, kind, metadata} with metadata
// trimmed to {name, namespace, uid}. The result always fits.
func objectMinimal(obj map[string]any) map[string]any {
	out := make(map[string]any, 3)
	copyKey(out, obj, "apiVersion")
	copyKey(out, obj, "kind")
	meta := make(map[string]any, 3)
	if source, ok := obj["metadata"].(map[string]any); ok {
		for _, key := range []string{"name", "namespace", "uid"} {
			copyKey(meta, source, key)
		}
	}
	out["metadata"] = meta
	return out
}

// copyKey copies src[key] into dst when present.
func copyKey(dst, src map[string]any, key string) {
	if value, ok := src[key]; ok {
		dst[key] = value
	}
}

// shapeGet prunes the fetched object and reduces it until it satisfies both
// server.max_object_bytes (per object) and server.max_response_bytes (whole
// response). truncated is true whenever the object was reduced.
func (s *Server) shapeGet(provider, contextName string, res policy.Resource, namespace, name string, obj *unstructured.Unstructured) getOutput {
	pruned := pruneObject(obj)
	levels := []map[string]any{pruned, objectSkeleton(pruned), objectMinimal(pruned)}

	level := 0
	for level < len(levels)-1 {
		envelope := getOutput{
			Provider:  provider,
			Context:   contextName,
			Resource:  res.String(),
			Namespace: namespace,
			Name:      name,
			Object:    levels[level],
			Truncated: level > 0,
		}
		if marshalSize(levels[level]) <= s.cfg.Server.MaxObjectBytes &&
			marshalSize(envelope) <= s.cfg.Server.MaxResponseBytes {
			break
		}
		level++
	}
	return getOutput{
		Provider:  provider,
		Context:   contextName,
		Resource:  res.String(),
		Namespace: namespace,
		Name:      name,
		Object:    levels[level],
		Truncated: level > 0,
	}
}

// fitObject reduces a pruned object to fit server.max_object_bytes and reports
// whether the object was reduced.
func (s *Server) fitObject(obj *unstructured.Unstructured) (map[string]any, bool) {
	pruned := pruneObject(obj)
	if marshalSize(pruned) <= s.cfg.Server.MaxObjectBytes {
		return pruned, false
	}
	skeleton := objectSkeleton(pruned)
	if marshalSize(skeleton) <= s.cfg.Server.MaxObjectBytes {
		return skeleton, true
	}
	return objectMinimal(pruned), true
}

// marshalSize returns the serialized size of v, or maxJSONSize when v cannot be
// marshaled (forcing reduction).
func marshalSize(v any) int {
	data, err := json.Marshal(v)
	if err != nil {
		return maxJSONSize
	}
	return len(data)
}

// jsonResult encodes v as a single JSON text content block.
func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}
