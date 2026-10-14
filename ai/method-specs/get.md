# get

## Purpose

Fetch a single Kubernetes object by name, under policy.

## Inputs

| Field     | Type   | Required | Notes                                                    |
|-----------|--------|----------|----------------------------------------------------------|
| provider  | string | yes      | Logical provider name.                                   |
| context   | string | yes      | Kubeconfig context; must match the provider's `contexts`.|
| resource  | string | yes      | `group/resource[/subresource]` or an alias.              |
| namespace | string | no       | Required for namespaced resources; omitted for cluster-scoped. |
| name      | string | yes      | Object name.                                             |

A `namespace` supplied for a cluster-scoped resource is rejected with a validation error, not reported as
not-found.

## Required capability

`<resource>:get` — the canonical `resource` with verb `get`. A matching `deny` rule (which may carry
capabilities and filters) overrides any `allow` rule that appears later.

## Kubernetes API call(s)

- Discovery to canonicalise `resource` (ADR 0012).
- `GET` the object: namespaced via the namespaced resource interface, cluster-scoped via the cluster
  resource interface.

## Authorization

1. Resolve the provider and context; the context must match the provider's `contexts`.
2. Canonicalise `resource` (fail-closed on ambiguity/unknown).
3. Validate that `namespace` is present for namespaced resources and absent for cluster-scoped ones.
4. Policy-only pre-check ignoring label filters: a matching scope-only `deny` rule, or the absence of a
   granting `allow` rule, denies as "not found" **without** an API call.
5. Fetch the object.
6. Full authorization with the object's labels and, if enabled, the namespace marker; the first applicable
   rule wins (`allow` grants, `deny` denies).
7. On deny, report "not found"; otherwise return the fetched object.

## Behavior / limits

- `metadata.managedFields` is always stripped; an object larger than `server.max_object_bytes` is reduced
  to `{apiVersion, kind, metadata}`, then (if still oversized) to `{name, namespace, uid}`, and flagged
  (`truncated`).
- The whole response is bounded by `server.max_response_bytes` (see `output.md`).
- The returned object is the one that was authorized; no second fetch occurs.

## Input validation

- `provider` and `context` are matched against the configuration and the kubeconfig; unknown values are
  rejected.
- `resource` is canonicalised (ADR 0012); unknown or ambiguous values are rejected.
- `namespace` and `name` are validated as Kubernetes names (DNS label/subdomain) and length-bounded.
- Control characters are rejected to prevent log injection.

## Errors

- `not found` — the object does not exist, or the request was denied (indistinguishable).
- `forbidden` (with HTTP status) — the kubeconfig identity lacks RBAC permission for the resource.
- `ambiguous resource: <name>` — the name matches more than one group; use `group/resource` or
  `core/resource` (ADR 0012).
- `unknown resource: <name>` — the resource could not be resolved, or does not support `get`.
