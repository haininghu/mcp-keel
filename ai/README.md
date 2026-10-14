# ai/ — agent documentation

This directory holds the durable, human-readable rationale for `mcp-keel`: why the system is shaped the
way it is, and the exact contract of every MCP tool. Prefer these documents over `git log`.

## Contents

| Folder             | Purpose                                                                 |
|--------------------|-------------------------------------------------------------------------|
| `architecture.md`  | Components and the shared authorization pipeline, with diagrams — **start here**. |
| `config-reference.md` | The authoritative configuration field reference.                     |
| `threat-model.md`  | Assets, adversary, trust boundaries and mitigations.                     |
| `testing.md`       | Test layers and the bypass matrix.                                       |
| `adr/`             | Architecture Decision Records: one decision per file, immutable once accepted. |
| `method-specs/`    | Specification of each MCP tool and the shared authorization pipeline.    |

## How to add

- **A decision** (`adr/NNNN-short-title.md`): copy the Status/Context/Decision/Consequences shape from
  `adr/0001-record-architecture-decisions.md`. ADRs are numbered sequentially and are **not edited** after
  acceptance; supersede them with a new ADR instead.
- **A tool** (`method-specs/<tool_name>.md`): follow the template in `method-specs/README.md`
  (Purpose, Inputs, Required capability, Kubernetes API call(s), Authorization, Behavior/limits, Errors).

## Ground rules

- English, concise, factual. Markdown lines <= 120 characters.
- No secrets, tokens, response bodies, or invented features.
- Keep the docs in sync with the code: if behavior changes, update the matching spec or ADR in the same
  change.

Start with `../AGENTS.md` for the repo map, commands and invariants.
