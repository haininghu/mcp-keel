# 0001. Record architecture decisions

## Status

Accepted.

## Context

`mcp-keel` is a security-sensitive project: its authorization semantics must be auditable and must not
change silently. We need a lightweight, durable record of why the system is shaped the way it is, so that
future changes can be judged against the original intent.

## Decision

We keep Architecture Decision Records (ADRs) in `ai/adr/`, one decision per file, numbered sequentially
(`NNNN-short-title.md`). Each ADR has:

- **Status** — Proposed, Accepted, Superseded.
- **Context** — the forces at play.
- **Decision** — what we decided.
- **Consequences** — what follows, including trade-offs and what becomes harder.

ADRs are **not edited** after acceptance; a changed decision is recorded as a new ADR that supersedes the
old one. Behavior changes must update the relevant ADR or method spec in the same change.

## Consequences

- Reading `ai/adr/` in order reconstructs the design rationale without relying on `git log`.
- Reviewers can point at a specific ADR when discussing a change.
- The process adds a small documentation cost to every behavioral change.
