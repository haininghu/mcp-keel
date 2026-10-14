# authorization

## Purpose

The shared evaluation pipeline used by every capability-gated tool: it turns a
`(provider, context, namespace, resource, verb, name, labels)` tuple into an allow/deny decision, with the
namespace-marker overlay layered on top for every capability.

## Inputs

| Field      | Type                | Notes                                                        |
|------------|---------------------|--------------------------------------------------------------|
| provider   | string              | Logical name; must be registered.                            |
| context    | string              | Must match one of the provider's `contexts` globs.           |
| namespace  | string              | The namespace; empty for a cluster-scoped resource or an all-namespaces list. |
| resource   | string              | Canonical `group/resource[/subresource]`, core = blank.      |
| verb       | `policy.Verb`       | `get` or `list` in v1.                                       |
| name       | string              | Object name for `get`; empty for `list`.                     |
| labels     | `policy.LabelSet`   | The target object's labels; always available for `get`/`list`.|

For `list`, `name` is empty; name filters are capability filters evaluated per item.

The `context` is matched against the provider's `contexts`; a context outside the provider is denied. The
`resource` is canonicalised through discovery (ADR 0012) before matching; the same canonical value is used
for the API call. A rule's scope is `namespaces`: globs match namespaced requests and the literal `""`
matches cluster-scoped requests (matched only by that literal entry; ADR 0004).

The scope (namespaced vs. cluster-scoped) is a property of the **resolved resource** (discovery), not of
the namespace string: an all-namespaces `list` also has an empty namespace. The guard uses the resource's
scope, not the namespace string, to decide whether the `""` marker applies.

## Required capability

N/A — this is the evaluator used by all tools.

## Kubernetes API call(s)

- Discovery (`ServerPreferredResources` / RESTMapper) for resource canonicalisation.
- A namespace `get`/`list` when the namespace marker is enabled and the matched grant is not exempt.

## Authorization

1. Resolve the provider and context from the registry.
2. Validate arguments (scope vs. namespace, name, bounds).
3. Canonicalise the resource (fail-closed on ambiguity/unknown).
4. Optional **pre-check** with the dimensions known before the fetch (scope, `resource`, `verb`, and the
   name for `get`, so a `names` filter is evaluable for `get`), ignoring labels and the marker. A `deny`
   rule whose evaluable conditions all match denies here without an API call; otherwise the request
   proceeds if some rule could grant the capability.
5. Fetch the object(s) when labels are needed for the final decision.
6. **Final decision**: evaluate the ordered rules with namespace, labels and (if enabled) the namespace
   marker. A rule applies when its scope matches AND one of its capabilities matches the requested
   `resource:verb` AND that entry's filters pass; the **first applicable rule wins** (`allow` grants,
   `deny` denies). A `get` returns the object that was authorized (no re-fetch); a `list` evaluates per
   item and drops denied items server-side only.
7. On allow, return the result; map errors with `mapKubeError`.

Decision reasons (all fail closed unless allowed):

- `no matching rule` — no rule applied (unknown provider/context/namespace/scope, or no matching
  capability).
- `context not in provider` — the requested context does not match the provider's `contexts`.
- `denied by rule` — an applicable `deny` rule won.
- `label requirement not met` / `excluded label present` — exact, case-sensitive; exclude wins.
- `name requirement not met` / `name excluded` — glob match on `metadata.name`.
- `marker present` / `marker check failed` — namespace marker, non-exempt capability.
- `ambiguous resource` / `unknown resource` — canonicalisation failed.

## Behavior / limits

- Rules are ordered; the first applicable rule wins (scope + capability + filters).
- A `deny` rule may list capabilities; with none it denies every capability in its scope. A `deny` rule
  whose conditions are all evaluable before the fetch short-circuits; a label-dependent `deny` is evaluated
  after the fetch.
- A filter that does not pass means the rule **does not apply** (fall-through). Exclusions therefore belong
  in `deny` rules, not in an `allow` capability's `exclude`.
- Deny-by-default: if no rule applies, access is denied.
- `*` as a verb is allowed only on `deny` rules. `*` as a resource is effect-dependent: on an `allow` rule
  it never matches subresources or the sensitive set; on a `deny` rule it matches everything (ADR 0004).
- Object filters (`labels`/`names`) are always evaluable for `get`/`list`, because the labels and the name
  ship with the object. A condition that needs a separate, fallible fetch (the namespace marker) is
  fail-closed: if it cannot be obtained, the request is denied.
- Labels and marker state are never cached across requests.
- The namespace marker is a capability-level default-deny overlay: every capability is denied in a marked
  namespace unless the matched capability entry is exempted with `namespace_marker: allow`. The check is
  fail-closed.

## Errors

At the tool boundary, a denied, filter-excluded or marker-protected object is mapped to the **same
response as a non-existent object** ("not found"), so the denial does not confirm that the object exists.
The precise reason is logged server-side only.
