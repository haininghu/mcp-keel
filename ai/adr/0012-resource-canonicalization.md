# 0012. Resource canonicalization (strict)

## Status

Accepted.

## Context

mcp-forj learned (bug 0005, then 0009) that authorization must use the same canonical identifier as the
backend call, otherwise a deny rule can be bypassed with an alternative spelling. Kubernetes is worse than
GitLab: a resource can be addressed by plural, singular, shortname or kind (`deployments`, `deployment`,
`deploy`, `Deployment`), it can live in different API groups (`events` in core **and** `events.k8s.io`),
and subresources (`pods/log`) are syntactically similar to `group/resource`.

## Decision

### One canonical form

- The canonical form is `[group/]resource[/subresource]`, **lowercase** and **versionless**, with the core
  group rendered as no prefix (`pods`, `pods/log`, `apps/deployments`).
- A tool argument and a configured capability are both resolved to exactly one canonical form, and that
  same form is used for **both** policy matching and the API call.
- Resolution happens **per `(provider, context)`** against that cluster's discovery, because CRDs differ
  between clusters. Config validation checks only syntax; full resolution is lazy and fail-closed.

### Resolution rules

1. Split the input on `/` into 1-3 tokens; more is invalid.
2. A token matches an `APIResource` by `name`, `singularName`, `shortNames` or `kind` (case-insensitive).
   Subresources are their own discovery entries (`pods/log`, `pods/exec`).
3. **1 token:** exactly one match -> use it; zero or more than one -> **deny** (unknown or ambiguous).
4. **2 tokens `a/b`:** exactly one reading of `group/resource` (a is a group) or `resource/subresource`
   (a is a resource, b a subresource) -> use it; both or neither -> **deny**.
5. **3 tokens `g/r/s`:** `group/resource/subresource`, validated.
6. **`core` is a reserved group token** for the empty (legacy) group: `core/pods` normalizes to `pods`.
   There is no real API group named `core`.
7. The discovered resource must list the requested verb in `Verbs`, otherwise **deny** (this rejects
   `list` on subresources such as `pods/log`, which supports only `get`).
8. The API call uses the **preferred version** from discovery; the policy matches the versionless form, so
   a deny covers every version.

### Ambiguity is rejected, not guessed

There is **no core precedence**: an unqualified name that resolves in more than one group (including core)
is denied. The caller must be explicit (`core/events` or `events.k8s.io/events`). This is deterministic and
cannot be bypassed, because the resolved form is used for policy and call alike.

### Sensitive set

Sensitive-set entries are canonical resource names (`configmaps`, `apps/deployments`); matching is against
the canonical form. A CRD `configmaps` in `example.com` becomes `example.com/configmaps` and is therefore
**not** sensitive. The built-in set is hardcoded canonical (core bare, RBAC as
`rbac.authorization.k8s.io/...`). `server.additional_sensitive_resources` entries are canonicalised per
request like capabilities; an ambiguous entry is added for all matching groups (fail-closed).

### Partial discovery

If a discovery group failed (`ErrGroupDiscoveryFailed`), the resolution may be incomplete and could miss an
ambiguity. To keep the ambiguity guarantee deterministic, **unqualified names are denied while discovery is
partial**; `core/...` and `group/...` still resolve (ADR 0014).

## Consequences

- Aliases, singular forms, shortnames, case and ambiguity can never produce a different policy result.
- A request that cannot be resolved unambiguously is denied rather than guessed.
- Installing a CRD whose name collides with a core resource (for example a CRD `pods`) makes the bare name
  ambiguous, so bare-name rules stop matching for it - fail-closed, but disruptive. Security-critical
  configs should use explicit forms (`core/pods`). There is deliberately no preflight diagnostic.
- Discovery is part of the authorization path; if the requested resource cannot be resolved, the request is
  denied (ADR 0014 covers discovery and partial failures).
- The detailed algorithm and test vectors live in `method-specs/resource-canonicalization.md`.
