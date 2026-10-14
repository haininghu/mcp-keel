# 0002. Deny-by-default capability policy

## Status

Accepted. The rule-matching parts are superseded by ADR 0011.

## Context

`mcp-keel` exposes an agent to Kubernetes clusters. A misconfiguration must never silently grant access.
We need an authorization model that is simple enough to audit by reading the configuration and that
defaults to "no access" when the configuration is incomplete.

## Decision

Authorize with a per-provider, ordered list of rules, evaluated against the tuple

```
(provider, context, namespace, resource, verb, name, labels)
```

- **Capabilities** are `<resource>:<verb>` strings validated at config load. v1 verbs are `get` and
  `list`. The resource part may be a core resource (`pods`), a grouped resource (`apps/deployments`), a
  subresource (`pods/log`) or the wildcard `*` (see ADR 0004). A `*` **verb** is allowed only on `deny`
  rules (ADR 0011).
- **Rules** carry a scope (`namespaces`, where the literal `""` selects cluster-scoped resources; see
  ADR 0004), an effect and a list of capabilities with optional filters. There is no rule-level `contexts`
  (contexts are a provider concern). **Rule matching** - scope plus capability plus filters, first match
  wins, deny rules may list capabilities - is defined in **ADR 0011**.
- Configuration is parsed **strictly** (`KnownFields`): an unknown key is an error, and a typo can never
  silently produce a different rule (see `ai/config-reference.md`).
- **Deny by default.** If no rule matches, access is denied.
- There is no configurable `default_effect` or `fail_mode`: deny-by-default and fail-closed are hardcoded.
- **Verbs do not imply each other.** `list` does not satisfy `get`, and vice versa.

The engine lives in `internal/policy`; config validation lives in `internal/config`.

## Consequences

- Reading the ordered config is enough to know what is granted; there is no hidden default allow.
- Rule order is security-critical: a broad `allow` above a `deny` hides the denial. Operators must order
  specific `deny` rules before broad `allow` rules. There is no config-load shadowing warning in v1.
- Kubernetes' many resource aliases require canonicalisation before matching (see ADR 0003); without it a
  deny rule could be bypassed.
