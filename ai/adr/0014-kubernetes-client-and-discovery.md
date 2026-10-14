# 0014. Kubernetes client and discovery

## Status

Accepted.

## Context

Three things were unspecified and would be invented during implementation:

- client-go defaults (QPS 5 / Burst 10) throttle an agent that lists resources;
- discovery of an aggregated API that is down makes `ServerPreferredResources` return
  `ErrGroupDiscoveryFailed`; naively treating that as a failure would deny **all** requests, including for
  healthy resources;
- timeouts and discovery caching were not fixed.

## Decision

### Discovery is partial-failure tolerant

- Discovery uses `ServerPreferredResources`. When it returns `ErrGroupDiscoveryFailed`, the successfully
  returned groups are still used; the failed groups are logged server-side only.
- When discovery is **complete**, a request is denied only when the requested resource cannot be resolved
  (unknown or ambiguous); a failure of an unrelated group never denies.
- When discovery is **partial** (a group failed), an **unqualified** name is denied, because the failed
  group could have made it ambiguous; `core/...` and `group/...` still resolve. This keeps the ambiguity
  guarantee deterministic (ADR 0012). The `*` resource wildcard is not resolved through discovery and is
  unaffected.

### Caching

- The RESTMapper and the resource lists are cached per `(provider, context)` for `discovery_cache_ttl`
  (default `10m`; `0` disables caching).
- On a `NoMatch`, the cache is invalidated once and discovery retried; a second `NoMatch` denies.
- The cache holds no authorization state (invariant 14).

### Client configuration

- Per `(provider, context)` the server builds and caches a dynamic client (for `get`/`list`) and a
  discovery client, from the same `rest.Config`; no auth state is cached.
- `qps` (default `20`) and `burst` (default `50`) override the low client-go defaults.
- `request_timeout` (default `30s`) bounds each request; `discovery_timeout` (default `10s`) bounds
  discovery separately.
- All client settings are **server defaults, overridable per provider**.

### Startup context validation

- Provider `contexts` are validated against the kubeconfig at startup (no cluster call): a literal context
  that does not exist is an **error**; a glob with zero matches is a **warning**.

## Consequences

- A down aggregated API does not break access to healthy resources.
- QPS/Burst, timeouts and the discovery cache TTL are tunable per provider.
- Misconfigured contexts are caught at startup rather than at request time.
- The detailed contract lives in `method-specs/discovery-and-caching.md`.
