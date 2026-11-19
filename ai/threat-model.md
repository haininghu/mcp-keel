# Threat model

`mcp-keel` runs locally, speaks MCP over stdio, and gives an agent read-only access to Kubernetes clusters
under a deny-by-default policy. This document states the assets, the adversary, the trust boundaries and
the mitigations, and maps each mitigation to the invariants in `../AGENTS.md`.

## Assets

- **Cluster access**: the kubeconfig credentials (tokens, client certificates and keys, exec plugin
  output).
- **Cluster data**: object contents, including Secrets (returned in v1 when explicitly granted) and pod log
  text (arbitrary application output).
- **Policy integrity**: the configuration determines what the agent may see.
- **Cluster availability**: the agent must not be able to overload the API server.
- **Monitoring availability**: Prometheus queries share the cluster path, so an expensive PromQL expression
  (subqueries, series cardinality) can consume Prometheus resources; the server bounds endpoints,
  transport and output but not PromQL cost (ADR 0017).

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
| Pod logs are a fixed `pods/log:get` read; an allow `*` never grants them | inv 7, ADR 0016 |
| Pod logs are a bounded single GET, capped by line and byte limits; no `follow` | inv 13, ADR 0016 |
| No authorization caches; discovery cache is fail-closed | inv 14, ADR 0014 |
| Content redaction of `get`/`list`/`logs` (best-effort; not a boundary) | inv 15, ADR 0015 |
| Prometheus is a fixed, synthetic `prometheus:query`/`:range`; no URL/path/port input to inject | inv 6, ADR 0017 |
| Prometheus proxy GET: redirects rejected, `LimitReader` body, concurrency sink | inv 13, ADR 0017 |

## Policy and RBAC are independent layers

- The kubeconfig identity's **RBAC** is the outer bound; the **policy** is an additional restriction.
  Effective visibility is the **intersection** of the two, and the policy never escalates beyond RBAC.
- A `forbidden` (HTTP 403) response tells the agent that the identity lacks RBAC for a policy-allowed
  resource. This is an accepted **rights oracle**: it reveals the identity's permissions, not object
  existence. It may be hidden in a later stage.

## Prompt injection

Object content (annotations, labels, ConfigMap and Secret data, pod logs) can contain attacker-controlled
text. The server returns it as data; the agent must treat it as untrusted. The policy bounds what the agent
can read but cannot stop the agent from being influenced by what it reads. This is why the policy must be
least-privilege and why output is bounded. Pod log text is arbitrary application output: it has no
structure the policy can filter, so the `logs` tool only bounds its size.

## Prometheus outbound path

A Prometheus query is the only outbound request the server issues beyond the Kubernetes API: a single
`GET` to the fixed path `/api/v1/namespaces/{ns}/services/{service}:{port}/proxy/api/v1/query` (or
`.../query_range`) on the API server. The namespace, service and port come only from configuration, agent
inputs travel exclusively through `url.Values`, redirects are rejected (so the bearer token is never
forwarded to a third host), and the body is read through a `LimitReader`. Prometheus metric label values are
a new data source whose content can carry injection payloads, exactly as object labels do.

The server bounds endpoints, transport, cost and output, but not PromQL semantics: subqueries
(`metric[30d:1s]`) and series cardinality (`{__name__=~".+"}`) live in the query string and can be
expensive even when range, step and point count are small. The operator must bound those on Prometheus
itself (`--query.max-samples`, `--query.timeout`, `--query.max-concurrency`). This is the documented
residual risk of ADR 0017, and it limits the "monitoring availability" asset, not the cluster itself.

## Non-goals (v1)

- Not a **confidentiality control for object content**: content is returned as stored, including
  `Secret.data` when `secrets:get` is explicitly granted and pod log text when `pods/log:get` is granted.
  Configured content redaction (ADR 0015) can strip known content, but it is **best-effort hygiene, not a
  boundary** - a typo'd field path, base64 secret values or the same value in another field/resource are not
  caught. `fields` cannot redact log text; only `replace` applies to it. `deny` and the sensitive set remain
  the confidentiality controls.
- Not a replacement for Kubernetes RBAC.
- Not hardened against a malicious local user with config/kubeconfig access.
- No defence against a compromised cluster or API server.
