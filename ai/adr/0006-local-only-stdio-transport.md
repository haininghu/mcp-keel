# 0006. Local-only stdio transport

## Status

Accepted.

## Context

mcp-forj serves two entry points: MCP over stdio and an optional git smart-HTTP proxy. For `mcp-keel`, the
first iteration targets a single developer or operator running the server on their own machine against
clusters they already have credentials for. A network listener would add authentication, TLS, multi-tenant
and remote-code-execution concerns that are out of scope.

## Decision

- The server speaks MCP over **stdio only**. There is no HTTP/TCP listener in v1.
- The server runs **locally**. In-cluster service account authentication and remote deployment are out of
  scope for v1.
- All logging goes to **stderr**; stdout is reserved for the MCP protocol.
- The configuration file and the kubeconfig are the trust boundary. The server does not accept credentials
  or kubeconfig locations from tool input.

## Consequences

- The threat model is a local one: the agent process and the server share a machine, and the config is
  controlled by the operator.
- Adding a remote transport later requires a new ADR covering authentication, authorization of the
  transport itself, and TLS.
- In-cluster execution can be added later by extending the cluster loader, without changing policy.
