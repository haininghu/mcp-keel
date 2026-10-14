# 0004. Cluster scope and wildcard safety

## Status

Accepted. Cluster-scope selection was reworked: `cluster_scope` is replaced by the `""` namespace marker.

## Context

Two Kubernetes-specific hazards have no direct mcp-forj equivalent:

1. **Cluster-scoped resources** (nodes, namespaces, persistentvolumes, clusterroles) have no namespace. A
   rule that matches namespaces must not accidentally grant them.
2. **The `*` wildcard.** A naive `*:get` would grant `secrets:get`, RBAC objects, service accounts,
   config maps and dangerous subresources (`pods/exec`, `nodes/proxy`) - enough to compromise a cluster
   under prompt injection.

A separate `cluster_scope` flag made the rule model two-dimensional and was found hard to reason about.

## Decision

### Cluster scope is the `""` namespace marker

- Every rule has a `namespaces` list that is non-empty (an entry may be the literal `""`). Entries are
  doublestar globs matched against namespaces, plus the literal empty string `""`, which selects
  **cluster-scoped** resources.
- A namespaced request matches a rule only through its namespace globs; `""` never matches a non-empty
  namespace. A cluster-scoped request matches only the `""` entry; globs never match cluster-scoped.
- **The empty namespace is matched only by the literal `""` entry, never by a glob.** In particular `*`
  and `**` never match `""`, so a namespace wildcard can never grant cluster-scoped access.
- A rule may list both, e.g. `namespaces: ["test-*", ""]`, to match namespaced and cluster-scoped requests.
- A rule's scope is selected **only** by `namespaces`; there is no `cluster_scope` field and no rule-level
  `contexts` (contexts are a provider-level concern).

For `list` without a namespace (all namespaces) the request namespace is empty, but the resource is
namespaced: authorization is per item with the item's namespace, and `""` entries do not apply. The
resource's scope (namespaced or cluster-scoped) comes from discovery, not from the request namespace.

### Wildcards are fail-closed

- `*` as a **verb** is allowed only on `deny` rules; an `allow` rule must name verbs explicitly so future
  verbs are never granted implicitly (ADR 0011).
- `*` as a **resource** is **effect-dependent**, because "as broad as safe" differs by effect:
  - on an `allow` rule it matches all resources **except** subresources and the built-in sensitive set, so
    an allow wildcard can never reach credentials, RBAC or subresources;
  - on a `deny` rule it matches **all** resources, including subresources and the sensitive set, so a deny
    wildcard is total.
  - in both cases it matches the resource name itself, not `group/*` (`apps/*` is not a wildcard form).
- The built-in sensitive set holds **canonical** resource names (core has no prefix):
  `secrets`, `serviceaccounts`, `configmaps`, `rbac.authorization.k8s.io/roles`,
  `rbac.authorization.k8s.io/rolebindings`, `rbac.authorization.k8s.io/clusterroles`,
  `rbac.authorization.k8s.io/clusterrolebindings`.
- Sensitive resources are **granted** only by explicit naming (`secrets:get`), in a namespaced or a
  cluster-scoped rule as appropriate.
- `server.additional_sensitive_resources` may **add** to the sensitive set; entries can never be removed,
  so the safe default cannot be weakened by configuration. Additional entries are canonicalised per
  request (like capabilities, ADR 0012); an ambiguous entry is added for **all** matching groups
  (fail-closed).
- Because an allow `*` also matches future CRDs, operators who want a fixed allow set must enumerate.

## Consequences

- A single `*:get` rule is safe by construction: it cannot reach credentials, RBAC or subresources.
- Cluster-scoped access is explicit and visible as `""` in a rule's `namespaces`, which keeps it auditable.
- Reading pod specs or logs can still expose secrets indirectly; this is documented, not blocked.
- Operators must name sensitive resources explicitly, which is slightly more verbose but intentional.
