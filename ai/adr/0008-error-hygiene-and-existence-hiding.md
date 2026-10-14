# 0008. Error hygiene and existence hiding

## Status

Accepted.

## Context

Raw Kubernetes errors can contain response bodies and reveal cluster internals. Separately, mcp-forj
learned (bug 0007) that a `.noai` denial must be indistinguishable from an unknown repository, otherwise
the denial itself confirms that the object exists.

## Decision

- The cluster layer maps native errors to neutral sentinels and attaches the HTTP status where available:
  401/403 -> forbidden, 404 -> not found, other non-zero -> generic failure. Response bodies are never
  surfaced.
- The server maps sentinels to safe messages and appends `(HTTP <n>)` when known.
- **A denied, label-excluded or namespace-marker-protected object is reported exactly like a non-existent
  one** ("not found"). The precise reason is logged server-side only.
- A `get` returns the object that was fetched and authorized; there is no second fetch (no time-of-check /
  time-of-use gap).
- For `list`, hidden items are counted server-side only. The response contains neither the hidden count nor
  any per-item denial reason.

## Consequences

- An agent cannot use the server as an existence oracle for objects it is not allowed to see.
- Operators diagnose denials from server logs, not from tool output.
- A coarse pre-check (capability not granted) can answer faster than a real not-found; this reveals
  configuration, not object existence, and is accepted (as in mcp-forj).
