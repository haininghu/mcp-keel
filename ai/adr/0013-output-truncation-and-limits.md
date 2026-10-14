# 0013. Output, truncation and limits

## Status

Accepted.

## Context

Tools return Kubernetes objects over stdio. Unbounded output is a denial-of-service vector (for example
500 items at 1 MiB each), and naively truncating serialized JSON yields invalid output. mcp-forj learned
(bugs 0006 and 0008) that listing must be bounded and must never disclose the number of hidden items. The
documentation also contradicted itself about whether credentials are ever returned, because a Kubernetes
`Secret.data` is exactly such data.

## Decision

### Output envelopes

- `get`: `{provider, context, resource, namespace, name, object, truncated}`.
- `list`: `{provider, context, resource, namespace, items, truncated}`.
- `resource` is the canonical form; `namespace` is `""` for an all-namespaces list.
- No item counts and no hidden-item count (ADR 0008).

### Pruning and truncation

- `metadata.managedFields` is **always** removed.
- An object larger than `server.max_object_bytes` after pruning is reduced to `{apiVersion, kind,
  metadata}`; if `metadata` itself is oversized, it is trimmed to `{name, namespace, uid}` (bounded), so
  the reduced object always fits. Valid JSON is never cut mid-structure.
- `get.truncated` means the object was reduced. `list.truncated` means the window or the response budget
  was exhausted, and/or an item was reduced.

### Response budget

- `server.max_response_bytes` (default `8388608`, 8 MiB) bounds the whole serialized response.
- `list` accumulates items until the budget is reached, then sets `truncated`.
- `get` reduces the object so the response fits.

### Redaction boundary

- The server's **own credentials** (kubeconfig tokens, client certificates and keys, exec plugin output)
  are never logged or returned. This is the server's authentication material.
- **Object content** is returned as stored by the API, including `Secret.data` when `secrets:get` is
  explicitly granted. `secrets` is in the built-in sensitive set, so `*` never reaches it and only
  explicit naming grants it.
- Redacting object **content** (for secrets and for other sensitive resources) is deferred to a later
  stage; v1 returns content as-is.

## Consequences

- Output is bounded and always valid JSON.
- The number of hidden items is never disclosed.
- Secret contents can reach the agent in v1. This is an accepted first-stage trade-off and is revisited
  together with a general content-redaction feature (not secrets-specific).
- `managedFields` are not available to the agent.
