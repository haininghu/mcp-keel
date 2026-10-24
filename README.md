# mcp-keel

A policy-governed [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI agents
controlled, **read-only** access to Kubernetes clusters. Access is **deny-by-default** and configured per
cluster or group of clusters. The first iteration supports only the `get` and `list` verbs; mutating verbs
(`create`, `update`, `patch`, `delete`), streaming operations (`logs`, `watch`, `exec`, `port-forward`) and
remote transports are planned for later stages.

`mcp-keel` is the Kubernetes sibling of [`mcp-forj`](../mcp-forj), a policy-governed MCP server for code
hosting providers. It reuses that project's authorization philosophy: a small, auditable, deny-by-default
rule engine that is shared by every tool.

> **Status: v1 implementation.** The server builds and passes its test suite. The API and configuration
> format may still change.

See [`AGENTS.md`](AGENTS.md) for the repo map, conventions and the security invariants, and
[`configs/config.example.yaml`](configs/config.example.yaml) for a fully commented example configuration.
Architecture decisions and per-tool specs live under [`ai/`](ai/README.md).

## Quick start

```bash
# 1. install the server (or build from a checkout with `make build`)
go install github.com/haininghu/mcp-keel/cmd/mcp-keel@latest

# 2. create a config from the documented example (configs/config.example.yaml)
#    and edit it: set kubeconfig, contexts and your rules

# 3. register the installed binary in your MCP host (see "Use with opencode")
```

The binary lands in `$(go env GOPATH)/bin/mcp-keel`; use that path (or an absolute
path to a locally built binary) as `command` in the host configuration.
`configs/config.yaml` is git-ignored and must never be committed. The server
speaks MCP over stdio only and logs to stderr; there is no HTTP listener and no
in-cluster service account. Once registered, ask the host to call the `get` or
`list` tools, for example list pods in a namespace your policy allows.

## Scope of v1

- **Verbs:** `get` and `list` only.
- **Transport:** MCP over **stdio** only. The server runs locally; there is no HTTP listener and no
  in-cluster service account support in v1.
- **Backend:** one Kubernetes backend (client-go). A flat cluster abstraction, not a plugin/factory layer.
- **Policy:** deny-by-default, firewall-style ordered rules evaluated against the tuple
  `(provider, context, namespace, resource, verb, name, labels)`. A rule applies when its scope matches
  AND either it is a `deny` rule without capabilities or one of its capabilities matches the request with
  passing filters; the first applicable rule wins.
- **Discovery:** `list_configured_rules` and `list_clusters` expose configured policy and context names,
  gated per provider by `policy_read: true`.

## Core concepts

| Concept              | Meaning                                                                                    |
|----------------------|--------------------------------------------------------------------------------------------|
| **Provider**         | A group of clusters, selected by kubeconfig context-name globs (`contexts`).               |
| **Context**          | A kubeconfig context, i.e. the cluster a request targets. The tool argument is `context`.  |
| **Capability**       | `<resource>:<verb>`, e.g. `core/pods:get`, `apps/deployments:list`, `*:get`.               |
| **Rule**             | Scope (`namespaces`, `""` = cluster-scoped) + `effect` + capabilities (each with filters). |
| **Namespace marker** | Optional label-based default-deny overlay (the analogue of mcp-forj's `.noai`).            |

## Tools

| Tool                    | Capability    | Description                                                       |
|-------------------------|---------------|-------------------------------------------------------------------|
| `get`                   | see rule      | Fetch one object by provider, context, resource, namespace, name. |
| `list`                  | see rule      | List objects, optionally by namespace, label selector, limit.     |
| `list_configured_rules` | `policy_read` | List configured rules for providers that opt in. Config only.     |
| `list_clusters`         | `policy_read` | List accessible provider/context names for opted-in providers.    |

`get`/`list` are gated by the matching rule's `resource:verb` capabilities. See
[`ai/method-specs/`](ai/method-specs/README.md) for the exact contracts.

## Configuration (preview)

```yaml
providers:
  - name: test-clusters
    kubeconfig: "${HOME}/.kube/config"
    contexts: ["*test*", "dev-play-cluster"]   # contexts, not cluster names
    rules:
      # Deny everything in this namespace (no capabilities = all).
      - namespaces: ["test-secrets"]
        effect: deny
      # Deny every operation on objects labelled "noai" (a DRY exclusion).
      - namespaces: ["test-*"]
        effect: deny
        capabilities:
          - "*:*":
              labels:
                require: ["noai"]
      # Otherwise allow reads.
      - namespaces: ["test-*", "namespace-a"]
        effect: allow
        capabilities:
          - core/pods:get                      # core; "core/" when the name is ambiguous
          - apps/deployments:get
          - core/pods/log:get                  # subresource: explicit
          - "*:get"                            # never matches secrets/RBAC/subresources
```

Key rules:

- **Deny by default.** No matching rule means access is denied.
- **First match wins, firewall-style.** A rule applies when its scope matches AND either it is a `deny`
  rule without capabilities or one of its capabilities matches the request with passing filters. Put
  specific `deny` rules before broad `allow` rules.
- **`deny` rules may list capabilities.** With none they deny every capability in their scope; `*` as a
  verb is allowed only on `deny` rules.
- **Filters are fall-through.** A filter that does not pass means the rule does not apply, so exclusions
  belong in `deny` rules, not in an `allow` capability's `exclude`.
- **`*` is fail-closed.** On an `allow` rule it never matches subresources or the built-in sensitive set
  (`secrets`, `serviceaccounts`, RBAC objects, `configmaps`); on a `deny` rule it matches everything.
  Sensitive resources must be named explicitly to be granted.
- **Cluster-scoped resources use the `""` namespace marker.** The literal `""` in a rule's `namespaces`
  selects cluster-scoped resources and is matched only by that literal entry; `*` and `**` never match
  `""`, so a namespace wildcard never leaks cluster-scoped access. There is no `cluster_scope` field and
  no rule-level `contexts`.
- **Resource identity is canonicalised** through discovery/RESTMapper. Aliases, singular forms, case and
  ambiguous names (`events`) fail closed, so a deny rule cannot be bypassed.
- **Errors are safe.** Denied, filter-excluded and marker-protected objects are reported exactly like
  non-existent ones, so the server never confirms that an object exists.
- **Namespace marker (optional).** `server.namespace_marker` marks a Namespace label as a default-deny
  overlay; a capability opts out with `namespace_marker: allow`.

## Security model

- The **config is the trust boundary.** Kubeconfig paths come from the config, never from tool input, and
  may contain exec credential plugins (arbitrary code execution).
- The server's **own credentials** (kubeconfig tokens, certificates, exec plugin output) are never logged
  or returned; a config dump is redacted. Object content is returned as stored (content redaction, for
  secrets and other resources, is planned for a later stage).
- Authorization happens **before** the cluster call, and any error fails **closed**.
- Listed objects are evaluated **per item** by the ordered rules (namespace + labels); hidden items are
  counted server-side only, never returned.
- **Policy and RBAC are independent layers.** Effective visibility is the intersection of the policy and
  the kubeconfig identity's RBAC; the policy never escalates beyond RBAC. See
  [`ai/threat-model.md`](ai/threat-model.md).
- **Content redaction (optional).** `providers[].redactions` strips configured content (static text,
  patterns, fields, specific env vars) from `get`/`list` results. It is best-effort hygiene, **not** a
  confidentiality boundary; `deny` remains the control. See
  [`ai/adr/0015-content-redaction.md`](ai/adr/0015-content-redaction.md).

## Requirements

- Go 1.27+
- A kubeconfig with contexts for the clusters you want to expose

## Build

```bash
make build        # -> bin/mcp-keel
make test         # unit tests
make test-e2e     # end-to-end smoke tests against a real API server (envtest)
make cover        # coverage report
make lint         # golangci-lint run (needs golangci-lint)
make check        # fmt-check + vet + test, what a pull request must pass
```

CI runs `fmt-check`, `vet`, `build` (including a cross-build), `test` and
`golangci-lint` on every push and pull request; see the [`.github/workflows/`](.github/workflows/)
and [`.golangci.yml`](.golangci.yml). Tagging `v*` builds release binaries with GoReleaser.

## Run

```bash
cp configs/config.example.yaml configs/config.yaml
# edit configs/config.yaml: set kubeconfig/contexts and your rules
./bin/mcp-keel -config configs/config.yaml
```

The server speaks MCP over stdio; all logging goes to stderr. `-config` defaults to
`configs/config.yaml`, and the `MCP_KEEL_CONFIG` environment variable overrides that default path.

### Use with opencode

Register the server as a local MCP server in `opencode.json` (absolute paths are recommended):

```json
{
  "mcp": {
    "mcp-keel": {
      "type": "local",
      "command": ["/path/to/bin/mcp-keel", "-config", "/path/to/configs/config.yaml"],
      "enabled": true
    }
  }
}
```

opencode loads its configuration once at startup, so restart it after editing.

## Commit conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Format:

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

Common types:

| Type       | Purpose                                                 |
|------------|---------------------------------------------------------|
| `feat`     | New feature                                             |
| `fix`      | Bug fix                                                 |
| `docs`     | Documentation only                                      |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test`     | Adding or correcting tests                              |
| `chore`    | Build, tooling, dependencies, ignore files              |

Examples:

```
feat(policy): support name filters on deny capabilities
fix(kube): fail closed when discovery is partial
docs(config): document the namespace marker
```

Use the imperative mood, lowercase after the colon, and no trailing period.
Breaking changes are marked with `!` (`feat(policy)!: ...`) and a
`BREAKING CHANGE:` footer. An authorization change updates the matching ADR
under [`ai/adr/`](ai/adr/) in the same commit.

## Docs

- [`AGENTS.md`](AGENTS.md) — repo map, conventions and authorization invariants.
- [`ai/architecture.md`](ai/architecture.md) — components and the shared authorization pipeline.
- [`ai/adr/`](ai/adr/) — architecture decision records (start at `0001`).
- [`ai/method-specs/`](ai/method-specs/) — specifications of every MCP tool.
- [`ai/config-reference.md`](ai/config-reference.md) — authoritative configuration field reference.
- [`ai/threat-model.md`](ai/threat-model.md) — assets, adversary, trust boundaries and mitigations.
- [`ai/testing.md`](ai/testing.md) — test layers and the bypass matrix.
- [`configs/config.example.yaml`](configs/config.example.yaml) — documented example configuration.

## License

MIT License, Copyright © 2026 Henning Voß. See [LICENSE](LICENSE).

