# method-specs

Specifications of every MCP tool exposed by `mcp-keel`, plus the shared authorization pipeline.

## Template

Each tool spec has:

- **Purpose** — what the tool is for.
- **Inputs** — the JSON schema fields, types and bounds.
- **Required capability** — the `resource:verb` (or provider flag) that gates the tool.
- **Kubernetes API call(s)** — the exact operations performed.
- **Authorization** — the pipeline steps specific to the tool.
- **Behavior / limits** — bounds, truncation, filtering.
- **Errors** — safe messages and their meaning.

## Index

| Spec                          | Contents                                                          |
|-------------------------------|-------------------------------------------------------------------|
| `authorization.md`            | The shared pipeline used by every capability-gated tool.          |
| `resource-canonicalization.md`| Resource identifier -> one canonical form for policy and call.    |
| `discovery-and-caching.md`    | Per-context discovery, partial-failure tolerance and caching.     |
| `output.md`                   | Shared output envelope, pruning, truncation and limits.           |
| `redaction.md`                | Configured content redaction of get/list results (ADR 0015).      |
| `get.md`                      | `get` — fetch one object by name.                                 |
| `list.md`                     | `list` — list objects with per-item authorization.                |
| `list_configured_rules.md`    | `list_configured_rules` — expose configured rules (config only).  |
| `list_clusters.md`            | `list_clusters` — expose accessible provider/context names.       |
