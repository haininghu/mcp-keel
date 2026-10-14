# 0005. Label and name filters, and the namespace marker

## Status

Accepted. Filters moved onto capability entries by ADR 0011.

## Context

mcp-forj scopes a grant with tag filters (`require`/`exclude`) and a `.noai` repository marker that denies
every capability unless explicitly exempted. Kubernetes has no repository file, but it has **labels** and
**names** on every object and **labels** on every namespace, which are the natural analogues.

## Decision

### Capability filters (labels and names)

- A capability entry (`resource:verb`) may carry a filter mapping with `labels` and `names`.
- `labels.require`: every listed label must be present. A bare `key` matches key presence; `key=value`
  matches the exact, case-sensitive value. `labels.exclude`: none may be present; **exclude wins**. A value
  listed in both is a config error.
- `names.include`: the object name must match at least one glob when the list is non-empty.
  `names.exclude`: the name must match none; **exclude wins**.
- Filters are evaluated against the target object. For `list`, they run **per item**.
- A filter that does not pass means the **rule does not apply** (fall-through, ADR 0011). A robust
  exclusion is therefore a `deny` rule, not an `exclude` on an `allow` capability; an `allow` filter is for
  positive scoping.
- The user-supplied `labelSelector` is passed to the API server for efficiency but **never replaces** the
  policy label check, which always runs client-side on each returned object.

### Namespace marker (optional overlay)

- `server.namespace_marker` configures a **label key on a Namespace** that acts as a capability-level
  default-deny overlay: when enabled, every capability is denied for objects in a marked namespace unless
  the matched capability entry is exempted with `namespace_marker: allow`.
- The marker applies only to **namespaced** resources. Cluster-scoped resources have no namespace and are
  not marker-checked.
- The marker is disabled by default. When enabled it costs one extra API call per request (a namespace
  `get`, or a namespace `list` for an all-namespaces `list`); there is **no cross-request cache**.
- The marker needs `get`/`list` RBAC on namespaces; without it the fail-closed check denies every
  non-exempt request. This is an operational footgun to be aware of.
- A marker check failure denies (fail-closed), and a marker denial is reported indistinguishably from a
  non-existent object (see ADR 0008).

## Consequences

- Grants can be scoped precisely without new capabilities.
- The marker is an integrity/governance control, not a confidentiality control: exempted reads still
  return content.
- Enabling the marker makes every non-exempt request one API call more expensive; this is accepted for
  correctness.
- Label matching is exact and case-sensitive; there are no label-value globs in v1.
