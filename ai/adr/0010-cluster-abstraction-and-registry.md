# 0010. Cluster abstraction and registry

## Status

Accepted.

## Context

mcp-forj defines a provider interface, a registry and a `RegisterFactory`/`init` plugin mechanism, because
it supports several backends (GitLab first, GitHub and Forgejo planned) and needs to avoid an import cycle.
`mcp-keel` v1 has exactly one backend type: Kubernetes. Copying the factory layer would be indirection
without a payoff.

## Decision

- Define a narrow `internal/kube` abstraction:
  - a `Cluster` interface exposing `Get`, `List` and resource resolution (`RESTMapper`);
  - a **registry** keyed by `(provider, context)` that lazily builds and caches a client from the
    provider's kubeconfig.
- There is **no** `RegisterFactory`/`init` plugin mechanism in v1. Adding a backend type later is a new
  ADR.
- The policy package (`internal/policy`) does not import `kube`. It depends on small interfaces (for
  example a label/namespace checker) so it stays backend-agnostic and testable with fakes.
- Discovery results (RESTMapper) may be cached per `(provider, context)` with a short TTL. Invalidation is
  fail-closed: an unknown resource is denied, and a failed discovery denies.
- Clients may be reused across requests; they carry no authorization state.

## Consequences

- The code is simpler than mcp-forj's provider layer while keeping the same seam for tests.
- The authorization core remains independent of client-go, so it can be unit-tested without a cluster.
- This is a deliberate deviation from mcp-forj ADR 0004; it is justified by the single backend type.
- If a second backend type (for example an aggregated API or a mock cluster) is added, it plugs in behind
  the same `Cluster` interface rather than a factory registry.
