# AGENTS.md

Instructions for AI agents (and humans) working on **mcp-keel**.

## What this project is

A policy-governed [Model Context Protocol](https://modelcontextprotocol.io) server written in Go. It
exposes tools that let an AI agent inspect Kubernetes clusters, read-only, under a deny-by-default policy.

- Transport: MCP over **stdio** only. All logging goes to **stderr**.
- Backend: Kubernetes via client-go. A flat cluster abstraction (`internal/kube`), no plugin factory.
- Verbs in v1: `get`, `list` only. Mutating and streaming verbs are out of scope.
- Authorization: **deny-by-default**, driven by a human-readable YAML config.
- The design mirrors `../mcp-forj`; see its `ai/architecture.md` for the reference philosophy.

## Status

v1 implementation in place: `internal/{config,policy,kube,server}` and `cmd/mcp-keel` build and pass the
test suite. Treat this file and `ai/` as the contract; when behavior changes, update the matching ADR/spec.

## Planned repository map

| Path                            | Contents                                                        |
|---------------------------------|-----------------------------------------------------------------|
| `cmd/mcp-keel`                  | Entrypoint and wiring (`main.go`).                              |
| `internal/config`               | YAML config loading, defaults, validation, secret redaction.    |
| `internal/policy`               | Capabilities, firewall rule engine, marker-exemption flag.      |
| `internal/kube`                 | Cluster abstraction, kubeconfig loading, discovery/RESTMapper.  |
| `internal/server`               | MCP server, tool handlers, argument validation, limits.         |
| `ai/`                           | Architecture overview, ADRs, method specs.                      |
| `configs/config.example.yaml`   | Documented example configuration.                               |
| `.github/`, `.goreleaser.yaml`  | CI (fmt/vet/test/lint), workflow audit and release.             |
| `.aiignore`                     | Paths AI tooling must not read (secrets, artifacts, IDE state). |
| `README.md`, `AGENTS.md`        | User-facing overview and this file.                             |

## Commands (once the implementation exists)

```bash
make build     # build bin/mcp-keel
make test      # go test ./...
make test-race # go test -race ./...
make cover     # coverage report
make vet       # go vet ./...
make fmt       # gofmt -s -w .
make fmt-check # fail if gofmt -l . prints anything (writes nothing)
make lint      # golangci-lint run (needs golangci-lint)
make check     # fmt-check + vet + test (what a PR must pass, writes nothing)
make tidy      # go mod tidy
make run       # go run ./cmd/mcp-keel -config ${CONFIG:-configs/config.yaml}
```

Equivalent direct commands: `go build ./...`, `go vet ./...`, `go test ./...`,
`golangci-lint run ./...` (configured in `.golangci.yml`), `gofmt -l .` (must print nothing).

### Pre-finish checklist

1. `gofmt -s -w .` then confirm `gofmt -l .` prints nothing.
2. `go vet ./...`
3. `golangci-lint run ./...` (configured in `.golangci.yml`)
4. `go test -count=1 ./...`
5. `go build ./...`

## CI

- `.github/workflows/ci.yaml` - `make fmt-check`, `make vet`, `make build`,
  `make test` and a cross-build on push/PR.
- `.github/workflows/golangci-lint.yaml` + `.golangci.yml` - golangci-lint
  (pinned version) on push/PR. Only linters that find bugs or security issues
  are enabled, plus the `gofmt` and `misspell` style checks; gosec and gocritic
  run with every rule.
  - Discard deliberately ignored errors explicitly (`_, _ = fmt.Fprintln(...)`).
  - Pass large structs by pointer and range over slices by index (gocritic
    `hugeParam`/`rangeValCopy`).
  - Silence a false positive only at its site with
    `//nolint:<linter> // <rule>: <reason>`, never by disabling the rule.
- `.github/workflows/release.yaml` + `.goreleaser.yaml` - release binaries on
  `v*` tags. Validate config changes with `goreleaser check`.
- `.github/workflows/zizmor.yaml` - audits the workflows and Dependabot config
  with [zizmor](https://docs.zizmor.sh/) (`pedantic` persona) on push/PR. Check
  workflow changes locally with `zizmor --persona pedantic .`: pin actions to
  a full commit SHA with a version comment, set `persist-credentials: false`
  on checkout, keep `setup-go` caching off, declare `permissions: {}` at the
  workflow level and grant (and comment) only what each job needs.
- `.github/dependabot.yml` - weekly updates for GitHub Actions and Go modules,
  with a 7-day cooldown.

## Conventions

- Documentation and code comments are in **English**.
- Every **exported** identifier has a doc comment starting with its name.
- Markdown lines are at most **120 characters**.
- No secrets in the repo. `configs/config.yaml` and `opencode.json` are git-ignored; `.aiignore` additionally
  keeps secrets, build artifacts and IDE state out of AI tooling context.
- Small, focused commits with a `type:` prefix: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`.
- Prefer Go **1.27 stdlib** helpers: `slices`, `maps`, `min`/`max`, `errors.AsType`, `strings.Cut`.
- Do not add dependencies without a clear need. Planned deps: the MCP SDK, `doublestar/v4`, `yaml.v3`
  and `k8s.io/client-go` (+ `apimachinery`).
- Do not change authorization semantics silently; update `ai/adr` instead.

## Invariants (must not break)

Authorization is the product. These rules are security-critical:

1. **Deny by default.** No rule match means access is denied.
2. **Rules are ordered and first-match-wins.** A rule applies when its scope matches AND one of its
   capabilities matches the request AND that capability's filters pass. Put specific `deny` rules before
   broad `allow` rules.
3. **`deny` rules may list capabilities.** A `deny` rule with no capabilities denies every capability in
   its scope (it can short-circuit before the fetch); a `deny` rule with capabilities denies when one
   matches the request and its filters pass. A `deny` rule may carry capability filters (`labels`,
   `names`).
4. **Config is parsed strictly and validated at load.** `KnownFields` rejects unknown keys; unknown
   verbs, malformed resource identifiers and bad patterns are rejected. See `ai/config-reference.md`.
5. **Authorize before the cluster call.** Every capability-gated tool authorizes first and fails closed on
   any error that prevents the decision. Discovery is partial-failure tolerant: when it is complete, only
   an unresolved or ambiguous **requested** resource denies; while it is **partial**, an unqualified name
   is denied (a failed group could have made it ambiguous) and `core/...`/`group/...` resolve (ADR 0014).
6. **Resource identity is canonicalised.** The tool argument is resolved through discovery/RESTMapper to
   one canonical form (`group/resource[/subresource]`, core = blank), and that same form is used for BOTH
   policy matching and the API call. Aliases, singular/plural forms, shortnames, case and ambiguous names
   (`events`) must never produce a different policy result; ambiguity fails closed.
7. **Wildcards are fail-closed.** On an `allow` rule, `*` never matches subresources and never matches the
   built-in sensitive set (canonical names: `secrets`, `serviceaccounts`, `configmaps`,
   `rbac.authorization.k8s.io/roles`, `rbac.authorization.k8s.io/rolebindings`,
   `rbac.authorization.k8s.io/clusterroles`, `rbac.authorization.k8s.io/clusterrolebindings`). On a `deny`
   rule, `*` matches everything, including subresources and the sensitive set. Sensitive resources require
   explicit naming to be granted. The set can be extended (entries canonicalised per request; an ambiguous
   entry protects all matching groups), never reduced.
8. **Cluster scope uses the `""` namespace marker.** Every rule has a `namespaces` list (non-empty; an
   entry may be `""`); the literal `""` selects cluster-scoped resources and is matched **only** by that
   literal entry, never by a glob
   (`*` and `**` never match `""`), so a namespace wildcard never grants cluster-scoped access. There is
   no `cluster_scope` field and no rule-level `contexts`.
9. **Verbs do not imply each other.** `list` does not satisfy `get`, and vice versa.
10. **Capability filters are match predicates.** `labels.require` (all present) and `labels.exclude`
    (none present; exclude wins) are evaluated against the object's labels; a bare key matches key
    presence, `key=value` matches exactly and case-sensitively. `names.include`/`names.exclude` match the
    object name. A filter that does not pass means the **rule does not apply** (fall-through), so
    exclusions belong in `deny` rules. The user-supplied `labelSelector` is a convenience passed to the API
    server and never replaces the policy label check. An optional namespace marker
    (`server.namespace_marker`) is a capability-level default-deny overlay; a capability may opt out with
    `namespace_marker: allow`.
11. **Existence is hidden.** A denied, filter-excluded or namespace-marker-protected object is reported
    exactly like a non-existent one. The precise reason is logged server-side only.
12. **Credentials never leak.** Kubeconfig paths come from config, never from tool input. The server's own
    credentials (tokens, client certificates and keys, exec plugin output) and raw error response bodies
    are never logged or returned; a config dump is redacted. Object content is returned as stored
    (ADR 0013).
13. **Output is bounded and quiet.** `list` uses a bounded scan window and caps items; the whole response
    is bounded by `server.max_response_bytes`; `metadata.managedFields` is always stripped and an oversized
    object is reduced to `{apiVersion, kind, metadata}`. The number of hidden items is never returned (only
    a `truncated` flag for the caller's own window). See ADR 0013.
14. **No authorization caches.** Labels and marker state are resolved per request; discovery may use a
    short-lived per-`(provider, context)` cache (`discovery_cache_ttl`) with fail-closed invalidation on a
    `NoMatch` (ADR 0014).

## Authorization flow

1. Resolve the provider and context (`context` must match the provider's `contexts`).
2. Canonicalise the resource via discovery/RESTMapper (fail-closed on ambiguity/unknown).
3. Validate arguments (namespace vs. cluster scope, name, bounds).
4. Optional **pre-check** with the dimensions known before the fetch (scope, `resource`, `verb`, and the
   name for `get`): a matching scope-only `deny` denies without an API call; otherwise proceed if some
   rule could grant the capability.
5. Fetch the object(s) when labels are needed for the final decision.
6. **Evaluate the ordered rules** with namespace, labels and (if enabled) the namespace marker: the first
   applicable rule wins (`allow` grants, `deny` denies). Map any denial to "not found".
7. Perform the cluster call and map errors to safe messages.

## Where to look

- **System overview / flow**: `ai/architecture.md`.
- **Configuration reference**: `ai/config-reference.md`.
- **Threat model**: `ai/threat-model.md`.
- **Testing strategy**: `ai/testing.md`.
- **Architecture decisions**: `ai/adr/` (start at `0001`).
- **MCP tool/operation specifications**: `ai/method-specs/`.
- **Docs index**: `ai/README.md`.

When you change behavior, update the relevant ADR/spec; do not rely on `git log` alone.
