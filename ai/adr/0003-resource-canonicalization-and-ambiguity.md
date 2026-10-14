# 0003. Resource canonicalization and ambiguity

## Status

Superseded by ADR 0012 (strict resource canonicalization), which pins down the algorithm.

## Context

mcp-forj learned (bug 0005, then 0009) that authorization must use the same canonical identifier as the
backend call, otherwise a deny rule can be bypassed with an alternative spelling (case, numeric id).
Kubernetes is worse than GitLab because a resource can be addressed in many ways:

- Plural / singular / shortname: `deployments`, `deployment`, `deploy`.
- API groups: `deployments` lives in `apps`, `events` exists in core **and** in `events.k8s.io`,
  `ingresses` historically in `extensions` and now in `networking.k8s.io`.
- Subresources: `pods/log` is syntactically similar to `group/resource`.

## Decision

- The canonical form of a resource is `group/resource[/subresource]`, with the core group rendered as an
  empty prefix (`pods`, `pods/log`, `apps/deployments`, `events.k8s.io/events`).
- A tool argument or a configured capability is resolved through discovery/RESTMapper to exactly one
  canonical form. That **same** form is used for BOTH policy matching and the API call.
- Resolution is **fail-closed**:
  - An ambiguous name (`events` matching two groups) is rejected; the caller must specify `group/resource`.
  - An unknown name is rejected.
  - Case is normalised to lowercase; configured patterns must match the canonical lowercase form.
- Config validation checks the syntax at load; full resolution happens lazily at request time and requires
  cluster access. Discovery results may be cached per `(provider, context)` with a short TTL and
  fail-closed invalidation (see ADR 0010).
- The canonical form is logged when a configured capability does not match, so operators can spot typos.

## Consequences

- Aliases, singular forms, shortnames and case can never produce a different policy result.
- A request that cannot be resolved unambiguously is denied rather than guessed.
- Operators may occasionally have to write `group/resource` explicitly (for example `events.k8s.io/events`).
- Discovery becomes part of the authorization path; its failure denies the request.
