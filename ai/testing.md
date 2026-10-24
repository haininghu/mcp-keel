# Testing strategy

Authorization is the product, so the tests must prove the invariants and the fail-closed boundaries, and
catch bypasses. The policy engine is backend-agnostic, so most of it is testable without a cluster.

## Layers

1. **Policy engine unit tests** (`internal/policy`): table-driven evaluation of first-match-wins,
   `deny` with and without capabilities, `allow`/`deny` with `labels`/`names` filters and fall-through, the
   `""` cluster marker, and the namespace-marker exemption. Backend dependencies are injected interfaces,
   so fakes suffice.
2. **Canonicalization tests** (ADR 0012): the test vectors from `method-specs/resource-canonicalization.md`,
   including alias, case, `core/`, group-vs-subresource and ambiguity.
3. **Config tests**: strict parsing (unknown keys rejected), validation errors, defaults, and golden valid
   configurations.
4. **Server/tool tests** with a fake cluster (`k8s.io/client-go/dynamic/fake` plus a fake RESTMapper):
   per-item `list` filtering, the output envelope, truncation and the response budget, and error hygiene.
5. **Race tests**: `go test -race ./...`.
6. **Fail-closed boundary tests**: discovery failure, **partial** discovery failure, marker-check failure,
   and unknown/ambiguous resources.

## Bypass attempts and their required outcome

| Attempt | Required outcome |
|---------|------------------|
| deny on `apps/deployments`, request `deploy` / `Deployment` | denied (same canonical form) |
| `*:get` | never reaches secrets, RBAC objects, config maps or subresources |
| `namespaces: ["*"]` or `["**"]` | never matches cluster-scoped (`""`) |
| broad `allow` above a specific `deny` | the deny is shadowed (documented; no warning in v1) |
| namespace marker whose check fails | denied (fail-closed) |
| a denied / filter-excluded object | reported exactly like a non-existent one |
| hidden list items | the count is never returned |
| an oversized object | valid JSON, reduced, flagged `truncated` |
| server credentials | never present in output or logs |
| a redacted field path matches nothing | no-op, warned once (best-effort, not fail-closed) |
| a redaction cap breached | object not returned (`get`: not found; `list`: dropped) |
| overlapping `replace` matches | the first matching rule's marker wins (deterministic) |
| a plaintext secret value in `Secret.data` | NOT caught by `replace` (base64); only `fields: remove data` protects |
| a redaction rule with an unresolvable/ambiguous resource | skipped + warned (capability logic) |
| a redaction `replace`/`text` literal | never returned by `list_configured_rules`, never logged |

## Commands

```bash
go test ./...
go test -race ./...
go vet ./...
gofmt -l .        # must print nothing
```

## Notes

- Tests must not require a real cluster; use the dynamic fake and a fake RESTMapper.
- Every security-relevant behavior change should add or update a case in the bypass table.
