# 0007. Kubeconfig and credential handling

## Status

Accepted.

## Context

Kubernetes credentials live in a kubeconfig. A kubeconfig is not inert data: `users[].user.exec` runs an
arbitrary program to obtain a token, and the file contains tokens, client certificates and keys. It must
be treated as trusted configuration, and its contents must never reach the agent or the logs.

## Decision

- The kubeconfig path comes **only** from the configuration (`provider.kubeconfig` or `server.kubeconfig`).
  It is never accepted from tool input.
- Path precedence: `provider.kubeconfig` > `server.kubeconfig` > `$KUBECONFIG` > `~/.kube/config`.
  A `~` prefix and whole-string `${NAME}` environment references are expanded; the resolved path must exist
  and be readable, otherwise startup fails.
- The `context` tool argument selects a context; it is matched against the provider's `contexts` globs and
  never selects a kubeconfig path.
- The server's **own credentials** (kubeconfig tokens, client certificates and keys, exec plugin output)
  and response bodies are **never logged and never returned** by any tool. Errors surface only a safe
  message and, where useful, an HTTP status.
- **Object content** is returned as stored by the API, including `Secret.data` when `secrets:get` is
  explicitly granted (see ADR 0013). Redacting object content is deferred to a later stage.
- Config secrets use a redacting `Secret` type so that `fmt`, `slog`, JSON and YAML dumps of the config are
  safe by construction.
- The example configuration documents that exec credential plugins execute code and must be treated as
  trusted.

## Consequences

- A compromised agent cannot point the server at an attacker-controlled kubeconfig.
- Startup fails loudly if the kubeconfig is missing, before any request is served.
- Operators remain responsible for the kubeconfig's contents and its exec plugins.
