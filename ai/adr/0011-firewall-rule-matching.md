# 0011. Firewall-style rule matching

## Status

Accepted. Supersedes the rule-matching parts of ADR 0002 and the deny-rule restriction in AGENTS.md
invariant 3.

## Context

mcp-forj evaluates a rule by matching the **container** (a repository) and then looking up the capability;
a `deny` rule is scope-only and must not list capabilities. Mapped onto Kubernetes, a rule would match
only the cluster context and namespace, and `deny` could only deny a whole scope. Two needs cannot be
expressed:

- "forbid every operation on objects matching a predicate" (a kind, a name pattern, a label);
- a robust, non-repetitive exclusion that a broader `allow` cannot defeat.

An `exclude` filter on an `allow` rule is not enough: in a fall-through model a later, broader `allow`
overrides it, and the same exclude would have to be repeated on every capability.

## Decision

Adopt a **firewall-style, symmetric** rule model.

- A rule has a **scope** (`namespaces`, where the literal `""` selects cluster-scoped resources; see
  ADR 0004), an **effect** (`allow` / `deny`) and a list of **capabilities** (`resource:verb`), each
  optionally with a **filter** (`labels`, `names`, `namespace_marker`). There is no rule-level `contexts`.
- A rule **applies** iff the scope matches AND one of:
  - the rule is a `deny` rule with no capabilities (it denies every capability in its scope); or
  - at least one capability entry matches the requested `resource:verb` AND all of that entry's filters
    pass.
- Rules are evaluated in order; the **first applicable rule wins**. `allow` grants, `deny` denies. If no
  rule applies, access is denied (deny-by-default).
- A `deny` rule **may list capabilities**; with none it denies every capability in its scope.
- A filter that does not pass means the rule **does not apply** (fall-through), not a hard deny.
  Exclusions are therefore written as `deny` rules placed **before** broader `allow` rules.
- `*` as a **verb** is allowed only on `deny` rules. An `allow` rule must name verbs explicitly so future
  verbs are never granted implicitly; a `deny` rule may use `*` because denying is fail-closed.
- `*` as a **resource** is effect-dependent: restricted on an `allow` rule (no subresources, no sensitive
  set), total on a `deny` rule (ADR 0004).
- Capability filters keep the compact single-key mapping form.

## Consequences

- "Forbid every operation on objects matching X" is a first-class `deny` rule.
- Exclusions are DRY: one `deny` rule instead of an `exclude` on every capability.
- Rule order is security-critical: a broad `allow` above a `deny` hides the denial (first-match-wins).
  This is documented; there is no config-load shadowing warning in v1.
- Filters are evaluated once the object is known: `resource`/`verb` (and, for `get`, the name) are known
  before the fetch; label filters and `list` items are evaluated after the fetch. A scope-only `deny`
  still short-circuits before the fetch.
- This **deviates from mcp-forj**, where deny rules carry no capabilities and match only the container.
  mcp-forj is to be adapted analogously in a later change; until then the two projects differ.
- AGENTS.md invariant 3 and ADR 0002 are updated accordingly.
