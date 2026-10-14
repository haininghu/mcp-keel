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

`contexts` may overlap between providers; a tool selects a provider by name and a context within it. All
rules of a provider apply to all of its contexts. The client settings above override the server defaults
for that provider's clusters.

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
| verb | string | yes | `get` \| `list`; `*` only on `deny` rules (ADR 0011) |
| `labels.require` | []string | no | `key` (present) or `key=value` (exact, case-sensitive) |
| `labels.exclude` | []string | no | `key` or `key=value`; wins over `require` |
| `names.include` | []string | no | doublestar globs on `metadata.name` |
| `names.exclude` | []string | no | doublestar globs; wins over `include` |
| `namespace_marker` | string | no | only the value `allow` (exempts the marker overlay) |

Resource grammar (ADR 0012): `resource`, `group/resource`, `resource/subresource`,
`group/resource/subresource`, `core/resource` (core alias) or `*`. An ambiguous unqualified name is
rejected (write `core/...` for a core resource whose name also exists in another group).

The built-in sensitive set uses canonical names (core bare; RBAC as `rbac.authorization.k8s.io/...`).
Additional entries are canonicalised per request; an ambiguous entry protects all matching groups.

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
