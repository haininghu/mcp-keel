# list

## Purpose

List Kubernetes objects, under policy, with per-item authorization.

## Inputs

| Field         | Type   | Required | Notes                                                        |
|---------------|--------|----------|--------------------------------------------------------------|
| provider      | string | yes      | Logical provider name.                                       |
| context       | string | yes      | Kubeconfig context; must match the provider's `contexts`.    |
| resource      | string | yes      | `group/resource[/subresource]` or an alias.                  |
| namespace     | string | no       | Omitted means all namespaces; omitted for cluster-scoped.    |
| labelSelector | string | no       | Passed to the API server; never replaces the policy check.   |
| limit         | int    | no       | Clamped to `server.max_list_items` (default `max_list_items`).|

A `namespace` supplied for a cluster-scoped resource is rejected with a validation error, not reported as
not-found.

## Required capability

`<resource>:list` — the canonical `resource` with verb `list`.

## Kubernetes API call(s)

- Discovery/RESTMapper to canonicalise `resource`.
- A bounded `LIST` (namespaced or all-namespaces), with the caller's `labelSelector` and a server-side
  limit window.
- A namespace `get`/`list` when the namespace marker is enabled and the matched grant is not exempt.

## Authorization

1. Resolve the provider and context.
2. Canonicalise `resource`.
3. Validate scope: cluster-scoped requires no `namespace`; namespaced allows a `namespace` or all.
4. Pre-check ignoring label filters:
   - `namespace` given: a matching scope-only `deny` rule, or the absence of a granting `allow` rule,
     denies for that namespace.
   - `namespace` omitted: check that `<resource>:list` is granted **anywhere** for the provider/context.
   - A failed pre-check returns an empty result (denied) without an API call.
5. Fetch a bounded window.
6. For each item, evaluate the ordered rules with the item's namespace and labels (and the marker); the
   first applicable rule wins. Denied items are dropped and counted server-side only.
7. Return the surviving items in the output envelope (see `output.md`).

## Behavior / limits

- The number of hidden items is never returned.
- If the caller's window or the response budget is exhausted, or an item was reduced, `truncated: true`;
  there are no `continue` tokens in v1.
- `metadata.managedFields` is always stripped; an item larger than `server.max_object_bytes` is reduced to
  `{apiVersion, kind, metadata}`, then (if still oversized) to `{name, namespace, uid}`. The whole response
  is bounded by `server.max_response_bytes`.
- Items are returned in the API server's order (typically name-sorted); the output is deterministic for a
  given cluster state.
- A `labelSelector` that matches nothing is not an error; it returns an empty list.

## Input validation

- `provider` and `context` are matched against the configuration and the kubeconfig; unknown values are
  rejected.
- `resource` is canonicalised (ADR 0012); unknown or ambiguous values are rejected.
- `namespace` is validated as a Kubernetes name; `labelSelector` and `limit` are length-/range-bounded.
- Control characters are rejected to prevent log injection.

## Errors

- A denied `list` (no matching rule, capability not granted, or a matching `deny`) returns an empty
  `items` list with `truncated: false` — not an error, so existence is not disclosed.
- `forbidden` (with HTTP status) — the kubeconfig identity lacks RBAC list permission.
- `ambiguous resource` / `unknown resource` — canonicalisation failed.
