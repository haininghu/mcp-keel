# Configuration reference

The authoritative field reference for the mcp-keel YAML configuration. Configuration is parsed with
`KnownFields(true)`: an unknown key is an error, so a typo can never silently produce a different rule.

The file is loaded from the `-config` flag, which defaults to `configs/config.yaml` and is overridden by
the `MCP_KEEL_CONFIG` environment variable.

## Top level

| Field | Type | Required | Default | Validation |
|-------|------|----------|---------|------------|
| `version` | int | no | `1` | must be `1` |
| `server` | object | no | `{}` | see below |
| `providers` | list | yes | - | at least one, unique names |

## `server`

| Field | Type | Required | Default | Validation |
|-------|------|----------|---------|------------|
| `name` | string | no | `mcp-keel` | non-empty |
| `log_level` | enum | no | `info` | `debug` \| `info` \| `warn` \| `error` |
| `request_timeout` | duration | no | `30s` | `> 0` |
| `discovery_timeout` | duration | no | `10s` | `> 0` |
| `discovery_cache_ttl` | duration | no | `10m` | `>= 0` (`0` disables caching) |
| `qps` | number | no | `20` | `> 0` |
| `burst` | int | no | `50` | `> 0` |
| `max_list_items` | int | no | `500` | `> 0`, `<= 1000` |
| `max_object_bytes` | int | no | `1048576` | `> 0` |
| `max_response_bytes` | int | no | `8388608` | `> 0` |
| `max_log_bytes` | int | no | `262144` | `> 0`, `<= 16777216`, `< max_response_bytes` |
| `max_log_lines` | int | no | `500` | `> 0`, `<= 10000` |
| `max_prometheus_query_length` | int | no | `8192` | `> 0`, `<= 65536` |
| `max_prometheus_query_range` | duration | no | `24h` | `> 0`, `<= 168h` |
| `max_prometheus_query_points` | int | no | `11000` | `> 0`, `<= 11000` |
| `max_prometheus_response_bytes` | int | no | `1048576` | `> 0`, `<= max_response_bytes`, `<= 8388608` |
| `prometheus_timeout` | duration | no | `10s` | `> 0` (bounded by the provider `request_timeout`) |
| `max_prometheus_concurrency` | int | no | `4` | `> 0`, `<= 32` |
| `kubeconfig` | string | no | `$KUBECONFIG` or `~/.kube/config` | path exists and is readable |
| `additional_sensitive_resources` | []string | no | `[]` | resource names, canonicalised per request; additive only |
| `namespace_marker` | object | no | disabled | see below |

### `server.namespace_marker`

| Field | Type | Required | Default | Validation |
|-------|------|----------|---------|------------|
| `enabled` | bool | no | `false` | - |
| `label` | string | no | `mcp-keel.io/noai` | valid Kubernetes label key |

## `providers[]`

| Field | Type | Required | Default | Validation |
|-------|------|----------|---------|------------|
| `name` | string | yes | - | unique, non-empty |
| `kubeconfig` | string | no | `server.kubeconfig` | path exists and is readable |
| `contexts` | []string | yes | - | non-empty; doublestar globs on context names |
| `policy_read` | bool | no | `false` | enables `list_configured_rules` / `list_clusters` |
| `rules` | list | yes | - | may be empty (a `policy_read`-only provider) |
| `qps` | number | no | `server.qps` | `> 0` |
| `burst` | int | no | `server.burst` | `> 0` |
| `request_timeout` | duration | no | `server.request_timeout` | `> 0` |
| `discovery_timeout` | duration | no | `server.discovery_timeout` | `> 0` |
| `discovery_cache_ttl` | duration | no | `server.discovery_cache_ttl` | `>= 0` |
| `prometheus` | list | no | `[]` | see below |

`contexts` may overlap between providers; a tool selects a provider by name and a context within it. All
rules of a provider apply to all of its contexts. The client settings above override the server defaults
for that provider's clusters. The Prometheus limits have no provider override; datasources apply to every
context of the provider, and `prometheus_timeout` is additionally bounded by the provider's
`request_timeout` (ADR 0017).

## `providers[].prometheus[]`

In-cluster Prometheus datasources reachable through the Kubernetes service proxy (ADR 0017). Empty
disables the Prometheus tools for the provider.

```yaml
prometheus:
  - name: main
    namespace: monitoring
    service: prometheus-k8s
    port: 9090
```

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| `name` | string | yes | lowercase identifier (`a-z0-9`, separators `-. _`), at most 253 bytes, unique per provider |
| `namespace` | string | yes | DNS-1123 label |
| `service` | string | yes | DNS-1123 subdomain |
| `port` | int | yes | `1..65535` |

The namespace, service and port are configuration, never tool input; there is no URL, path, port or
timeout argument on the tools. The datasource `name` is the policy `name` dimension and `names`-filter
key; the Service labels are the policy `labels` dimension. Datasource **names** are exposed by
`list_configured_rules` (for providers with `policy_read: true`); namespace, service and port are never
exposed by that tool.

## `providers[].rules[]`

| Field | Type | Required | Default | Validation |
|-------|------|----------|---------|------------|
| `namespaces` | []string | yes | - | list non-empty; globs plus the literal `""` marker |
| `effect` | enum | yes | - | `allow` \| `deny` (no default) |
| `capabilities` | list | allow: >= 1, deny: optional | - | `deny` with none denies every capability in scope |

- `namespaces` entries are matched against a request's namespace. The literal `""` selects cluster-scoped
  resources and is matched only by that literal entry, never by a glob (`*` and `**` never match `""`);
  ADR 0004.
- There is no rule-level `contexts`; contexts are a provider concern.

## `capabilities[]`

A capability is either a scalar `resource:verb` or a single-key mapping `resource:verb:` with a filter:

```yaml
capabilities:
  - core/pods:get
  - "apps/deployments:list"
  - core/pods/log:get          # subresource: explicit, never covered by `*`
  - "*:get":
      labels:
        require: ["managed-by=platform"]
        exclude: ["noai"]
      names:
        include: ["frontend-*"]
        exclude: ["*-debug"]
  - "core/pods:get":
      namespace_marker: allow
```

| Key | Type | Required | Validation |
|-----|------|----------|------------|
| resource | string | yes | see resource grammar below |
| verb | string | yes | `get` \| `list` \| `query` \| `range`; `*` only on `deny` rules (ADR 0011) |
| `labels.require` | []string | no | `key` (present) or `key=value` (exact, case-sensitive) |
| `labels.exclude` | []string | no | `key` or `key=value`; wins over `require` |
| `names.include` | []string | no | doublestar globs on `metadata.name` |
| `names.exclude` | []string | no | doublestar globs; wins over `include` |
| `namespace_marker` | string | no | only the value `allow` (exempts the marker overlay) |

The verbs `query` and `range` are valid only with the exact resource `prometheus` (the synthetic resource
of ADR 0017), never with the resource wildcard `*` and never in group- or subresource-qualified form;
`*:query`, `*:range` and `pods:query` are rejected at load. `prometheus:get` and `prometheus:list` keep
their discovery meaning (a Prometheus Operator CRD is not shadowed). A `deny` rule may use `prometheus:*`;
it expands to the synthetic query and range grants plus, when discovery resolves `prometheus`, to the CRD.

Resource grammar (ADR 0012): `resource`, `group/resource`, `resource/subresource`,
`group/resource/subresource`, `core/resource` (core alias) or `*`. An ambiguous unqualified name is
rejected (write `core/...` for a core resource whose name also exists in another group).

The built-in sensitive set uses canonical names (core bare; RBAC as `rbac.authorization.k8s.io/...`).
Additional entries are canonicalised per request; an ambiguous entry protects all matching groups.

The synthetic resource `prometheus` (ADR 0017) is resolved only for `query` and `range`, never through
discovery, and is also part of the set an allow `*` never matches. It is addressed by its bare name
`prometheus`, exactly.

`pods/log` is a subresource. The `logs` tool requests it with verb `get`, so it needs the explicit capability
`pods/log:get`; an `allow` `*` never matches subresources, while a `deny` rule with `*` as resource or verb
does cover it.

## `providers[].redactions[]`

Content redaction of `get` objects, `list` items and the `logs` text (ADR 0015, ADR 0016). It is best-effort
hygiene, **not** a confidentiality boundary; `deny` and the sensitive set remain the controls. Rules are
opt-in per provider.

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| `resources` | []string | no | canonical resource names (no `*`) |
| `namespaces` | []string | no | doublestar globs; the literal `""` = cluster-scoped |
| `names` | []string | no | doublestar globs on `metadata.name` |
| `labels.require` / `labels.exclude` | []string | no | as in the policy rules |
| `fields` | list | no | `{path, action: remove \| replace, marker?}` |
| `replace` | list | no | `{text \| pattern (RE2), marker?}` |

- All match dimensions are optional; an omitted dimension imposes no constraint. `resources` uses the
  **capability** canonicalisation: an unresolvable or ambiguous resource is skipped and warned.
- `fields.path` grammar: `.`, `[*]`, `[n]`, `["..."]` and the element predicate `[field=value]`
  (e.g. `spec.containers[*].env[name=TOKEN].value`).
- `replace` requires exactly one non-empty `text` (literal) or `pattern` (RE2); the marker replaces the
  whole match.
- The default marker is hardcoded (`[REDACTED]`); a per-entry `marker` overrides it.
- All matching rules apply (union), `fields` before `replace`. Caps are hardcoded; a breach fails closed.
- `fields` operates on object structure and has no effect on log text; `replace` applies to every string
  value and to the whole log text.
- The `text` literals are secret material: never returned by `list_configured_rules`, redacted in dumps.

Prometheus query results (ADR 0017) are redacted with the same rules. `resources: ["prometheus"]` resolves
the exact resource `prometheus` to the synthetic resource **before** discovery, so a Prometheus Operator CRD
can never shadow the rule. The match dimensions are the datasource namespace (from `prometheus[].namespace`),
the datasource name (from `prometheus[].name`, matched by `names`), and the Service labels (matched by
`labels`); the decoded JSON body is walked exactly like an object, so `fields` operates on the JSON structure
(`result[*].metric[...]`) and `replace` applies to every string value.

## Glob semantics

- doublestar, **case-sensitive**, anchored to the whole string (`test-*` does not match `xtest-a`); `*`
  does not cross `/`.
- Contexts, namespaces and resource identifiers are normally lowercase. The config loader warns when a
  pattern has a leading or trailing `*` (for example `*prod*`, which also matches `nonprod`).
- Kubernetes does not guarantee lowercase context names, and matching is case-sensitive, so a glob that
  does not account for a mixed-case context silently misses it (the loader warns only when a glob has zero
  matches).

## Startup validation

- `contexts` are checked against the kubeconfig at startup: a literal context that does not exist is an
  error; a glob with zero matches is a warning (ADR 0014).
