# resource-canonicalization

## Purpose

Turn a resource identifier from a tool argument or a configured capability into exactly one canonical form
that is used for both policy matching and the API call. It is the mcp-forj bug-0009 fix in Kubernetes form.

## Inputs

A resource identifier string, from either the tool argument `resource` or a capability's resource part.

Accepted forms:

| Form                          | Example                     |
|-------------------------------|-----------------------------|
| `resource`                    | `pods`, `deploy`, `events`  |
| `core/resource`               | `core/pods`, `core/events`  |
| `group/resource`              | `apps/deployments`          |
| `resource/subresource`        | `pods/log`                  |
| `group/resource/subresource`  | `apps/deployments/scale`    |
| `*`                           | `*` (wildcard, see ADR 0004)|

## Canonical form

`[group/]resource[/subresource]`, lowercase, versionless, core = no prefix. The `core/` prefix is an input
alias that normalizes to the bare form.

## Algorithm

1. Split on `/`. 1-3 tokens; more is invalid.
2. Build candidates from discovery. A token matches an `APIResource` by `name`, `singularName`,
   `shortNames` or `kind` (case-insensitive). Subresources appear as `resource/subresource` entries.
3. Resolve:
   - **1 token:** exactly one candidate -> take it; zero or several -> deny.
   - **2 tokens `a/b`:** exactly one of `group/resource` or `resource/subresource` resolves -> take it;
     both or neither -> deny.
   - **3 tokens:** `group/resource/subresource`, validated.
4. Reject the `*` wildcard mixed with anything (`*/x`, `x/*`) except as the whole resource.
5. Verify the resolved `APIResource.Verbs` contains the requested verb; otherwise deny.
6. Emit the canonical form; resolve the preferred version separately for the API call.

## Resolution is per cluster

Resolution uses the discovery of the request's `(provider, context)`, because CRDs differ between clusters.
A capability valid in one cluster may be unknown in another; the request is denied in the latter.

## Examples

| Input                    | Canonical                |
|--------------------------|--------------------------|
| `pods`                   | `pods`                   |
| `po`                     | `pods`                   |
| `deploy`                 | `apps/deployments`       |
| `Deployment`             | `apps/deployments`       |
| `core/pods`              | `pods`                   |
| `pods/log`               | `pods/log`               |
| `apps/deployments/scale` | `apps/deployments/scale` |
| `events` (ambiguous)     | deny - use `core/events` or `events.k8s.io/events` |
| `events.k8s.io/events`   | `events.k8s.io/events`   |

## Errors

- `ambiguous resource: <name>` - more than one group matches an unqualified name.
- `unknown resource: <name>` - no candidate, or the resource does not support the verb.

Both are request-shape errors, not policy denials; they are reported as such and never as "not found".
