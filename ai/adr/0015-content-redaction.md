# 0015. Content redaction of tool results

## Status

Accepted. Supersedes the "content redaction is deferred" statements in ADR 0007 and ADR 0013.

## Context

Policy rules decide **which objects** an agent may access, not **which content** those objects expose.
`get`/`list` return objects as stored, so an operator cannot currently strip a static token, an IP address,
a specific environment variable or secret material from a result the agent is otherwise allowed to read.
Operators need a configured, resource-scoped way to remove such content.

## Decision

### Placement

- Redaction is a **post-authorization transformation**: it runs only after a successful allow and the
  fetch, over the returned object(s), and it never authorizes or denies.
- It applies to `get` (the object) and `list` (each item), never to `list_configured_rules`/`list_clusters`.
- Order: `prune(managedFields)` -> **redact** -> reduce (`{apiVersion,kind,metadata}` / `{name,namespace,
  uid}`) -> response budget. Redaction therefore runs before reduction, so `metadata` (which reduction
  keeps) is already redacted.
- Rules are configured **per provider**, next to the policy `rules` (`providers[].redactions`). Redaction
  is **opt-in**: a provider without `redactions` returns content as stored.

### Matching

- A redaction rule matches on `resources`, `namespaces` (globs; the literal `""` selects cluster-scoped),
  `names` and `labels` - all **optional**; an omitted dimension imposes no constraint and all present
  dimensions must match (AND).
- `resources` are canonical (ADR 0012) and resolved per `(provider, context)`. They follow the
  **capability** logic: an unresolvable or ambiguous resource is skipped and warned (best-effort), and
  partial discovery is handled exactly as for capabilities. There is no `*`.

### Actions

- `fields`: `{path, action: remove|replace, marker?}`. Path grammar: `.`, `[*]`, `[n]`, `["..."]` and the
  element predicate `[field=value]`.
- `replace`: `{text | pattern (RE2), marker?}` - exactly one of `text`/`pattern`.
- The default marker is **hardcoded** (`[REDACTED]`); a per-entry `marker` overrides it, so different
  matches can be marked differently.
- **All** matching rules apply (union, most-restrictive) - deliberately the opposite of authorization.
  They run **phase-ordered**: every `fields` operation first, then `replace`; text/pattern replacement is a
  cascade-free interval union over the original string. For overlapping `replace` matches, the marker of
  the first matching rule in configuration order wins.

### Safety

- A structural walk over **string values only**; serialized JSON is never edited, and keys are never
  touched.
- Hardcoded caps (`max_work_bytes`, `max_depth`); a breach fails closed - the object is not returned
  (`get` -> "not found", `list` -> item dropped and `truncated` set). Unredacted content is never returned.
- Literal replacement text is **secret material**: never logged, never returned by `list_configured_rules`,
  redacted in config dumps.
- **No object drop** (content-based exclusion is a policy `deny`, not a second engine) and **no dynamic
  secret-value redaction** (see `method-specs/redaction.md` for the base64 and cross-resource limits).

### Best-effort, not a boundary

Redaction is **hygiene / defence-in-depth, not a confidentiality boundary**. A field path that matches
nothing is a silent no-op (a warning is logged once per rule). `deny` and the sensitive set remain the
confidentiality controls.

## Consequences

- Operators can strip known sensitive content from results without widening or narrowing authorization.
- Because it is best-effort, a typo'd path or a schema change can silently fail to redact; this is
  documented and surfaced by a warning, but it is not a guarantee.
- `Secret.data` is base64: `replace` (literal/pattern) cannot strip a plaintext secret value; only
  `fields: {path: data, action: remove}` protects secrets.
- Redaction adds a per-object walk cost, bounded by the hardcoded caps.
- `list_configured_rules` must expose redaction structure without the `text` literals.
