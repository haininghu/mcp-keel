# discovery-and-caching

## Purpose

Resolve a resource identifier to a canonical form (ADR 0012) and to a GVR for the API call, per
`(provider, context)`, tolerating partial discovery failures and caching the result.

## Inputs

| Field    | Type   | Notes                                             |
|----------|--------|---------------------------------------------------|
| provider | string | Logical provider name.                            |
| context  | string | Must match one of the provider's `contexts`.      |
| resource | string | The tool argument or configured capability part.  |

## Kubernetes API call(s)

- Discovery: `ServerPreferredResources` (and `ServerGroups`) against the context's discovery client.
- No object calls here; this only resolves identifiers.

## Behavior

1. Look up the cached discovery state for `(provider, context)`. If absent or older than
   `discovery_cache_ttl`, load it.
2. Load: call `ServerPreferredResources`. If it returns `ErrGroupDiscoveryFailed`, keep the returned
   (partial) resource lists and log the failed groups server-side only.
3. Build the RESTMapper from the resource lists and cache it.
4. Resolve the identifier with the algorithm in `resource-canonicalization.md`.
5. On `NoMatch`, invalidate the cache once and reload; a second `NoMatch` denies.
6. Verify the resolved resource supports the requested verb (`APIResource.Verbs`); otherwise deny.

## Limits and failure modes

- When discovery is complete, a failure of an unrelated group never denies a request whose resource
  resolved.
- While discovery is **partial** (a group failed), unqualified names are denied, because the failed group
  could have made the name ambiguous; `core/...` and `group/...` still resolve. The `*` wildcard is not
  resolved through discovery and is unaffected. This keeps the ambiguity guarantee deterministic.
- An unresolved or ambiguous resource denies (fail-closed).
- `discovery_cache_ttl: 0` disables caching; each request reloads.
- The cache is keyed by `(provider, context)` and holds no authorization state.

## Errors

- `unknown resource: <name>` - not resolved, or does not support the verb.
- `ambiguous resource: <name>` - more than one group matches an unqualified name.

Both are request-shape errors, not policy denials.
