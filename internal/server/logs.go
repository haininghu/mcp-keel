package server

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/haininghu/mcp-keel/internal/kube"
	"github.com/haininghu/mcp-keel/internal/policy"
)

// logsResource is the fixed resource the logs tool addresses. A pod log is the
// "log" subresource of "pods", so the policy matches "pods/log:get" (ADR 0012).
const logsResource = "pods/log"

// handleLogs implements the logs tool: resolve, validate, canonicalise the
// fixed pods/log resource, pre-check, fetch the pod, evaluate, apply the
// namespace marker, select the container, read a bounded log window, redact it
// and shape the response. Every denial and a redaction failure are reported as
// "not found" (ADR 0008, ADR 0015).
//
//nolint:gocritic // hugeParam: MCP SDK handler signature
func (s *Server) handleLogs(ctx context.Context, _ *mcp.CallToolRequest, in logsInput) (*mcp.CallToolResult, any, error) {
	cluster, err := s.resolveRegistry(in.Provider, in.Context)
	if err != nil {
		return nil, nil, err
	}

	if err = validateNamespace(in.Namespace); err != nil {
		return nil, nil, err
	}
	if err = validateName(in.Pod); err != nil {
		return nil, nil, err
	}
	if err = validateContainer(in.Container); err != nil {
		return nil, nil, err
	}
	if in.TailLines < 0 {
		return nil, nil, errors.New("tailLines must not be negative")
	}
	if in.SinceSeconds < 0 {
		return nil, nil, errors.New("sinceSeconds must not be negative")
	}

	res, err := canonicalizeResolve(ctx, cluster, logsResource)
	if err != nil {
		return nil, nil, err
	}
	namespaced, err := cluster.Namespaced(ctx, res)
	if err != nil {
		return nil, nil, resourceInspectionError(logsResource, err)
	}
	if !namespaced {
		return nil, nil, fmt.Errorf("unknown resource: %s is not namespaced", logsResource)
	}
	supported, err := cluster.SupportsVerb(ctx, res, policy.VerbGet)
	if err != nil {
		return nil, nil, resourceInspectionError(logsResource, err)
	}
	if !supported {
		return nil, nil, fmt.Errorf("unknown resource: %s does not support get", logsResource)
	}

	compiled, err := s.policyFor(ctx, in.Provider, in.Context, cluster)
	if err != nil {
		return nil, nil, err
	}
	proceed, reason := compiled.PreCheck(&policy.Request{
		Namespace:  in.Namespace,
		Namespaced: true,
		Resource:   res,
		Verb:       policy.VerbGet,
		Name:       in.Pod,
	})
	if !proceed {
		s.logger.Info("logs denied by pre-check",
			"provider", in.Provider, "context", in.Context, "resource", res.String(),
			"namespace", in.Namespace, "name", in.Pod, "reason", reason)
		return nil, nil, errNotFound
	}

	// Fetch the pod: its labels and container names are the input to the
	// pods/log decision and the log read. This needs RBAC read access to pods
	// in addition to pods/log, because log content itself carries no labels.
	base := res
	base.Subresource = ""
	fetched, err := cluster.Get(ctx, base, in.Namespace, in.Pod)
	if err != nil {
		return nil, nil, mapKubeError(err)
	}
	if fetched == nil {
		return nil, nil, errNotFound
	}

	labels := fetched.GetLabels()
	decision := compiled.Evaluate(&policy.Request{
		Namespace:  in.Namespace,
		Namespaced: true,
		Resource:   res,
		Verb:       policy.VerbGet,
		Name:       in.Pod,
		Labels:     policy.LabelSet{Known: true, Values: labels},
	})
	if !decision.Allowed {
		s.logger.Info("logs denied",
			"provider", in.Provider, "context", in.Context, "resource", res.String(),
			"namespace", in.Namespace, "name", in.Pod, "reason", decision.Reason)
		return nil, nil, errNotFound
	}

	if s.markerEnabled() && !decision.NamespaceMarkerExempt {
		marked, markerErr := cluster.NamespaceMarked(ctx, in.Namespace, s.markerLabel())
		if markerErr != nil {
			s.logger.Error("namespace marker check failed; denying",
				"provider", in.Provider, "context", in.Context,
				"namespace", in.Namespace, "error", markerErr.Error())
			return nil, nil, errNotFound
		}
		if marked {
			s.logger.Info("logs denied by namespace marker",
				"provider", in.Provider, "context", in.Context,
				"namespace", in.Namespace, "name", in.Pod)
			return nil, nil, errNotFound
		}
	}

	container, err := logContainer(fetched, in.Container)
	if err != nil {
		return nil, nil, err
	}

	// The engine must exist before the log read: a build failure fails closed
	// instead of returning unredacted content.
	engine, err := s.redactionFor(ctx, in.Provider, in.Context, cluster)
	if err != nil {
		return nil, nil, err
	}

	tail := s.clampLogLines(in.TailLines)
	limit := int64(s.cfg.Server.MaxLogBytes) + 1
	opts := kube.LogOptions{
		Container:  container,
		Previous:   in.Previous,
		Timestamps: in.Timestamps,
		TailLines:  &tail,
		LimitBytes: &limit,
	}
	if in.SinceSeconds > 0 {
		since := int64(in.SinceSeconds)
		opts.SinceSeconds = &since
	}

	raw, err := cluster.Logs(ctx, in.Namespace, in.Pod, opts)
	if err != nil {
		return nil, nil, mapKubeError(err)
	}

	content, err := engine.ApplyText(string(raw),
		redactionMatch(res, in.Namespace, true, in.Pod, labels))
	if err != nil {
		// A cap breach fails closed: the log is never returned unredacted.
		s.logger.Error("log redaction failed; denying",
			"provider", in.Provider, "context", in.Context, "resource", res.String(),
			"namespace", in.Namespace, "name", in.Pod)
		return nil, nil, errNotFound
	}

	out := logsOutput{
		Provider:  in.Provider,
		Context:   in.Context,
		Resource:  res.String(),
		Namespace: in.Namespace,
		Pod:       in.Pod,
		Container: container,
		Content:   content,
	}
	s.truncateLog(&out)
	return jsonResult(out)
}

// logContainer selects the container whose log to read. An explicit container
// wins; otherwise the pod must have exactly one container.
func logContainer(pod *unstructured.Unstructured, requested string) (string, error) {
	if requested != "" {
		return requested, nil
	}
	containers, found, err := unstructured.NestedSlice(pod.Object, "spec", "containers")
	if err != nil || !found {
		return "", errors.New("could not read the pod's containers")
	}
	if len(containers) != 1 {
		return "", fmt.Errorf("container is required: the pod has %d containers", len(containers))
	}
	entry, ok := containers[0].(map[string]any)
	if !ok {
		return "", errors.New("could not read the pod's containers")
	}
	name, _ := entry["name"].(string)
	if name == "" {
		return "", errors.New("could not read the pod's containers")
	}
	return name, nil
}

// truncateLog bounds the content to server.max_log_bytes and then to the whole
// serialized response budget. The budget check is exact: JSON escaping can
// expand log text (newlines, control characters), so the largest fitting prefix
// is found by binary search instead of estimating from the raw byte count. A cut
// is always made on a UTF-8 boundary and sets truncated.
func (s *Server) truncateLog(out *logsOutput) {
	if len(out.Content) > s.cfg.Server.MaxLogBytes {
		out.Content = utf8Prefix(out.Content, s.cfg.Server.MaxLogBytes)
		out.Truncated = true
	}
	if marshalSize(*out) <= s.cfg.Server.MaxResponseBytes {
		return
	}
	content := out.Content
	low, high := 0, len(content)
	for low < high {
		mid := (low + high + 1) / 2
		candidate := *out
		candidate.Content = utf8Prefix(content, mid)
		if marshalSize(candidate) <= s.cfg.Server.MaxResponseBytes {
			low = mid
		} else {
			high = mid - 1
		}
	}
	out.Content = utf8Prefix(content, low)
	out.Truncated = true
}

// utf8Prefix returns the longest prefix of s of at most n bytes that ends on a
// UTF-8 rune boundary.
func utf8Prefix(s string, n int) string {
	if n >= len(s) {
		return s
	}
	if n < 0 {
		n = 0
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
