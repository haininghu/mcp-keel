# 0016. Pod log access

## Status

Accepted.

## Context

Agents need pod logs to diagnose workloads, and Kubernetes RBAC models log reads as `get` on the `pods/log`
subresource. Three constraints shape the feature:

- The policy engine authorizes on `(namespace, resource, verb, name, labels)`, but log text has no labels;
  the labels live on the pod object.
- Log text is arbitrary application output with no schema, so a structural redaction walk has nothing to
  address.
- A log read is conceptually streaming (`kubectl logs -f`), which conflicts with the server's bounded,
  request/response, read-only model.

## Decision

### Fixed resource and verb

- The tool always targets the canonical subresource `pods/log` with verb `get`. It accepts no resource
  identifier, so no other subresource (for example `services/proxy`) is reachable.
- Authorization requires the explicit capability `pods/log:get`. An `allow` `*` never matches subresources
  (ADR 0004), so logs are never granted by a wildcard; a `deny` rule with `resource: "*"` or `verb: "*"` does
  cover them.

### Dedicated tool

- `logs` is a separate tool, not a mode of `get`: its inputs, bounds, container selection and output
  envelope differ from an object read.
- The authorization order is: canonicalise `pods/log` -> validate -> pre-check -> fetch the pod -> full
  evaluation with the pod's labels and name -> namespace marker -> fetch the log.
- The pod fetch exists because log text has no labels. The pod object is never returned; it only supplies
  the labels, the name and the container list.
- Denied, label-excluded, marker-protected and missing pods are all reported as `not found` (ADR 0008).

### Container selection and bounds

- `container` is required when the pod has more than one container; a single-container pod defaults to it.
- `tailLines` defaults to and is capped by `server.max_log_lines` (default 500, hard max 10000).
- `server.max_log_bytes` (default 262144, hard max 16 MiB, and less than `server.max_response_bytes`) caps
  the returned bytes. The tool requests `limitBytes = max_log_bytes + 1` to detect truncation and sets
  `truncated` when the extra byte is returned.
- `follow` is deliberately not exposed. The read is a bounded single GET, never a stream; mutating and
  streaming verbs remain out of scope.

### Redaction

- If the provider configures `redactions`, the `replace` phase applies to the whole log text after a
  successful allow and before the response budget (ADR 0015). `fields` has no target in text.
- Redaction remains best-effort hygiene, not a confidentiality boundary; `pods/log:get` is the
  confidentiality control.

## Consequences

- Every log request costs an extra API call for the pod object.
- Log text is arbitrary and untrusted: it can carry secrets and prompt-injection payloads, and the policy
  cannot filter its content. Only its size is bounded.
- No streaming: there is no `follow`, `tail -f` or watch; an agent re-requests a bounded window instead.
- A wildcard `allow` does not grant logs, so operators must add `pods/log:get` explicitly. Existing
  configurations therefore do not start exposing logs implicitly.
- The cluster must expose the `pods/log` subresource through discovery; otherwise the tool answers
  `unknown resource: pods/log`.
- The kubeconfig identity needs RBAC for both `pods/log` and `pods` `get` (for the pod fetch); a missing
  permission surfaces as `forbidden`.
