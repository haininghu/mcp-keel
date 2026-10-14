# Threat model

`mcp-keel` runs locally, speaks MCP over stdio, and gives an agent read-only access to Kubernetes clusters
under a deny-by-default policy. This document states the assets, the adversary, the trust boundaries and
the mitigations, and maps each mitigation to the invariants in `../AGENTS.md`.

## Assets

- **Cluster access**: the kubeconfig credentials (tokens, client certificates and keys, exec plugin
  output).
- **Cluster data**: object contents, including Secrets (returned in v1 when explicitly granted).
- **Policy integrity**: the configuration determines what the agent may see.
- **Cluster availability**: the agent must not be able to overload the API server.

## Adversary

- **Primary: an agent (LLM) under prompt injection.** Tool input is attacker-influenceable, and object
  fields returned by the cluster can themselves carry injection payloads.
- **Secondary: operator misconfiguration** (an over-broad rule).
- **Out of scope for v1:** a malicious local user who can read the config and kubeconfig (those are the
  trust boundary), and network attackers (stdio is local).

## Trust boundaries

- **Trusted:** the configuration file and the kubeconfig, both operator-controlled. Kubeconfig exec
  plugins execute code and are trusted.
- **Untrusted:** every tool argument, and every object field returned by the cluster. The server treats
  these as data, never as instructions.

## Mitigations

| Mitigation | Where |
|------------|-------|
| Deny by default; no matching rule denies | inv 1 |
| Ordered, first-match-wins rules | inv 2 |
| `deny` may list capabilities; filters fall through | inv 3, ADR 0011 |
| Strict config parsing and validation | inv 4, config-reference |
| Authorize before the call; fail closed | inv 5 |
| Canonicalisation (aliases, case, ambiguity) | inv 6, ADR 0012 |
| Wildcard safety (`*` cannot reach secrets/RBAC/subresources on allow) | inv 7, ADR 0004 |
| Cluster scope via the `""` marker | inv 8, ADR 0004 |
| Verbs do not imply each other | inv 9 |
| Label/name filters fail closed | inv 10, ADR 0005 |
| Existence is hidden | inv 11, ADR 0008 |
| Server credentials never logged or returned | inv 12, ADR 0007 |
| Output is bounded and quiet | inv 13, ADR 0013 |
| No authorization caches; discovery cache is fail-closed | inv 14, ADR 0014 |

## Policy and RBAC are independent layers

- The kubeconfig identity's **RBAC** is the outer bound; the **policy** is an additional restriction.
  Effective visibility is the **intersection** of the two, and the policy never escalates beyond RBAC.
- A `forbidden` (HTTP 403) response tells the agent that the identity lacks RBAC for a policy-allowed
  resource. This is an accepted **rights oracle**: it reveals the identity's permissions, not object
  existence. It may be hidden in a later stage.

## Prompt injection

Object content (annotations, labels, ConfigMap and Secret data, later pod logs) can contain
attacker-controlled text. The server returns it as data; the agent must treat it as untrusted. The policy
bounds what the agent can read but cannot stop the agent from being influenced by what it reads. This is
why the policy must be least-privilege and why output is bounded.

## Non-goals (v1)

- Not a **confidentiality control for object content**: content is returned as stored, including
  `Secret.data` when `secrets:get` is explicitly granted. Content redaction (for secrets and other
  resources) is future work.
- Not a replacement for Kubernetes RBAC.
- Not hardened against a malicious local user with config/kubeconfig access.
- No defence against a compromised cluster or API server.
