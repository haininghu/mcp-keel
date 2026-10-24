# output

## Purpose

The output contract shared by `get` and `list`: the JSON envelope, object pruning, truncation and the
response budget. It keeps output bounded and always valid JSON, and never discloses hidden-item counts.

## Envelopes

`get`:

```json
{
  "provider": "test-clusters",
  "context": "test-a",
  "resource": "pods",
  "namespace": "test-a",
  "name": "frontend-1",
  "object": { "apiVersion": "v1", "kind": "Pod", "metadata": {}, "spec": {}, "status": {} },
  "truncated": false
}
```

`list`:

```json
{
  "provider": "test-clusters",
  "context": "test-a",
  "resource": "pods",
  "namespace": "test-a",
  "items": [ {}, {} ],
  "truncated": false
}
```

| Field | Type | Notes |
|-------|------|-------|
| provider / context | string | Echo of the resolved request. |
| resource | string | Canonical resource form (ADR 0012). |
| namespace | string | `""` for a cluster-scoped resource or an all-namespaces list. |
| name | string | `get` only. |
| object | object | `get` only; the pruned Kubernetes object. |
| items | []object | `list` only; the pruned Kubernetes objects. |
| truncated | bool | See below. |

## Pruning

- `metadata.managedFields` is always removed.
- No other fields are dropped by default.

## Truncation

- If a pruned object still exceeds `server.max_object_bytes`, it is reduced to `{apiVersion, kind,
  metadata}`; if `metadata` is still oversized, it is trimmed to `{name, namespace, uid}` (bounded). The
  result is always valid JSON; bytes are never cut mid-structure.
- `get.truncated` is true when the object was reduced.
- `list.truncated` is true when the list window or the response budget was exhausted, and/or an item was
  reduced.

## Response budget

- `server.max_response_bytes` (default 8 MiB) bounds the serialized response.
- `list` adds items until the budget would be exceeded, then stops and sets `truncated`.
- `get` reduces the object until the response fits.

## Redaction

- Server credentials (kubeconfig tokens, certificates, exec plugin output) are never part of the output.
- Configured **content redaction** (ADR 0015) runs after a successful allow, over the object's string
  values, **before** pruning/reduction: `prune(managedFields)` -> redact -> reduce -> budget. It is
  best-effort hygiene, not a confidentiality boundary; a cap breach fails closed (the object is not
  returned). See `redaction.md`.

## Errors

Output is only produced after a successful, authorized call. Errors use the shared error hygiene
(ADR 0008): denied or filter-excluded objects are reported exactly like non-existent ones.
