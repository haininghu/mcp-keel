# redaction

## Purpose

The post-authorization transformation that removes configured content from `get`/`list` results. It is
**best-effort hygiene, not a confidentiality boundary** (ADR 0015); `deny` and the sensitive set remain the
confidentiality controls.

## Where it runs

`prune(managedFields)` -> **redact** -> reduce -> budget (ADR 0013). It applies to the `get` object and to
each `list` item, after a successful allow, and never to `list_configured_rules`/`list_clusters`.

## Configuration

Rules live under `providers[].redactions` (see `config-reference.md`). Redaction is opt-in per provider.

## Matching

A rule matches an object when all of its present dimensions match (AND); omitted dimensions impose no
constraint:

| Dimension    | Notes                                                                     |
|--------------|---------------------------------------------------------------------------|
| `resources`  | canonical (ADR 0012), resolved per `(provider, context)`; no `*`          |
| `namespaces` | doublestar globs; the literal `""` selects cluster-scoped resources       |
| `names`      | doublestar globs on `metadata.name`                                        |
| `labels`     | `require`/`exclude`, as in the policy (ADR 0005)                           |

`resources` follow the **capability** logic: an unresolvable or ambiguous resource is skipped and warned;
partial discovery is handled as for capabilities. There is no core precedence and no `*`.

## Actions

### `fields`

`{path, action: remove|replace, marker?}` - structural edits to the object.

Path grammar (minimal, validated at load):

- `.` separates segments; a segment is a bare key or a bracket-quoted key `["..."]` (for keys containing
  `.`, `/`).
- `[*]` selects all array elements, `[n]` a single index. `[*]` applies to arrays only; map values are not
  addressable and must be removed via their parent field.
- `[field=value]` is an element predicate on an array of maps: it selects elements whose `field` equals the
  exact, case-sensitive string `value`, e.g. `spec.containers[*].env[name=TOKEN].value`. The value runs to
  the first `]`; a `]` inside the value is a load error.

Semantics:

- `remove` on `...[name=TOKEN].value` removes only the `value` key; on `...[name=TOKEN]` it removes the
  whole element.
- `replace` replaces the terminal string value with the marker.
- A path that matches nothing is a **no-op** (logged once per rule); a `remove` of a parent makes later
  child paths no-ops.

### `replace`

`{text | pattern, marker?}` - textual replacement over **string values only**.

- `text` is a literal substring; `pattern` is an RE2 regex compiled at load. Exactly one is required, and
  it must be non-empty.
- The marker replaces the **entire** match; there is no capture substitution.

## Phases, determinism and markers

- **All** matching rules apply (union, most-restrictive) - the opposite of authorization.
- Phases: every `fields` operation first (in rule/list order), then `replace`.
- `replace` is a **cascade-free interval union** over the original string: a match never scans a marker
  inserted by another match.
- For overlapping `replace` matches, the marker of the **first matching rule in configuration order** wins.
- The default marker is hardcoded (`[REDACTED]`); `marker` per entry overrides it.

## Caps and failure

- Hardcoded `max_work_bytes` and `max_depth` bound the walk.
- A breach fails closed: the object is not returned - `get` answers like a denied object ("not found"),
  `list` drops the item and sets `truncated`. The reason is logged server-side only. Unredacted content is
  never returned.

## Limits (honest)

- **Base64:** `Secret.data` is base64; `replace` cannot strip a plaintext secret value. Protect secrets
  structurally with `fields: {path: data, action: remove}` (and `stringData`).
- **Not information-flow:** the same value in an unredacted field, resource, annotation or log is not
  caught. Redaction is pattern/field-based, not data-flow-based.
- **Silent no-op:** a typo'd path or a schema change can fail to redact; a warning is logged once per rule,
  but there is no guarantee.
- **No object drop, no dynamic secret-value redaction** (ADR 0015).

## Introspection

`list_configured_rules` may expose redaction structure (resources, scopes, field paths, patterns) but
**never** the `text` literals, which are secret material.
