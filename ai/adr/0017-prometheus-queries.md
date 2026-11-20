# 0017. Prometheus queries through the Kubernetes service proxy

## Status

Accepted.

## Context

`mcp-keel` analyses cluster state through the Kubernetes API only. Metrics are often the missing half of
a diagnosis: a pod is running, but the request rate, error rate or saturation is only visible in
Prometheus. Agents should be able to query Prometheus under the same deny-by-default policy, without
receiving a second, ungoverned data path.

Three constraints shape the feature:

- The server runs locally and reaches clusters through a kubeconfig. An in-cluster Prometheus is usually
  not directly reachable from the agent host.
- Prometheus has no object model that maps onto Kubernetes RBAC. A query endpoint is either usable or it
  is not; PromQL cannot be constrained per namespace or per object by the server.
- The existing policy engine authorizes `resource:verb` capabilities against
  `(namespace, resource, verb, name, labels)`. Prometheus queries do not have a Kubernetes resource, so
  the capability vocabulary must be extended rather than bent around `services/proxy`.

The chosen transport is the Kubernetes service proxy
(`/api/v1/namespaces/{ns}/services/{service}:{port}/proxy/...`). It reuses the kubeconfig credentials,
works for clusters without a direct network path, and leaves an audit trail in the API server. A direct
Prometheus URL would require a second credential and TLS configuration and would not solve reachability.

## Decision

### Datasources and transport

Each provider may configure zero or more Prometheus datasources:

```yaml
prometheus:
  - name: main
    namespace: monitoring
    service: prometheus-k8s
    port: 9090
```

The datasource name is unique within the provider and applies to every context of that provider. The
configuration is validated at load: the name is an identifier, the namespace and service are DNS-1123
names, and the port is an integer in `1..65535`. Named ports, URL paths and schemes are not configurable
in v1.

Namespace, service and port are configuration, never tool input. There is no URL, path or port argument
on the tools. The server builds exactly two paths:

- `GET .../proxy/api/v1/query` for an instant query;
- `GET .../proxy/api/v1/query_range` for a range query.

No other Prometheus endpoint is reachable. Admin, lifecycle (`/-/quit`, `/-/reload`), metadata, targets,
rules, alerts and the experimental APIs are out of scope. Only `GET` is used; a `POST` form would map to
the Kubernetes `create` verb and is not permitted.

### Capabilities

Prometheus has its own capability namespace:

- `prometheus:query` — instant query;
- `prometheus:range` — range query.

`prometheus` is a synthetic resource: it is resolved only for these two verbs and never through
discovery. `prometheus:get` and `prometheus:list` keep their existing meaning and continue to resolve
through discovery, so a Prometheus Operator CRD named `prometheus` is not shadowed.

The verbs `query` and `range` are valid only with the exact resource `prometheus`; group-qualified or
subresource forms and the resource wildcard are rejected at configuration load. An allow verb wildcard
is already invalid. An allow `*:get` never grants a Prometheus query because the verb differs. The
synthetic resource is also added to the set an allow `*` never matches, as defense in depth. A deny rule
may use `prometheus:*`; it expands to the synthetic `query` and `range` grants and, when discovery
resolves it, to the CRD resource. The synthetic half must survive partial or absent discovery, so a deny
never silently loses the Prometheus half.

The capability vocabulary is validated in the configuration layer. `policy.Build` validates structure
only; `matchesVerb`, `PreCheck` and `GrantsAnywhere` need no change.

### Authorization

A query is a normal policy request:

| Dimension | Value |
|-----------|-------|
| `namespace` | the datasource's namespace |
| `resource` | the synthetic resource `prometheus` |
| `verb` | `query` or `range` |
| `name` | the datasource name |
| `labels` | the labels of the Service object |

The namespace scope, `names` and `labels` filters and the namespace-marker overlay therefore apply
unchanged. `names` matches the **datasource name** (configuration), `labels` matches the **Service
labels** (cluster state); it is not the same object namespace and must be documented.

An unknown provider, context or datasource is a configuration error, following the precedent for unknown
providers. A missing, denied, filter-excluded or marker-protected Service is reported exactly like a
non-existent object.

### Request construction

Agent inputs (`query`, `time`, `start`, `end`, `step`) are encoded exclusively through `url.Values`,
never by string concatenation. Path segments come only from validated configuration. This prevents an
agent from injecting additional Prometheus parameters, truncating server-set parameters with `#` or `?`,
or breaking the path with `..` or percent-encoded separators.

- The server sets `timeout` itself on every request; the agent cannot pass `timeout`, `stats`,
  `lookback_delta`, `limit`, `max_series` or cost parameters.
- `query` rejects control characters and is limited to `server.max_prometheus_query_length` bytes.
- `time`, `start` and `end` are strict RFC 3339 timestamps; `step` is a strict positive duration.
- `end` must not precede `start`; the range and point count are checked before any API call.
- Redirects are not followed (`CheckRedirect` returns `http.ErrUseLastResponse`); a `3xx` response is an
  error. A followed redirect could send the API-server bearer token to another host.
- Only a `2xx` response with `application/json` is parsed. Everything else is a generic upstream error.

### Bounds and availability

The server enforces, with server-level defaults and hard upper bounds:

| Setting | Default | Hard bound |
|---------|---------|------------|
| `max_prometheus_query_length` | 8 KiB | 64 KiB |
| `max_prometheus_query_range` | 24 h | 7 d |
| `max_prometheus_query_points` | 11000 | 11000 |
| `max_prometheus_response_bytes` | 1 MiB | `max_response_bytes`, at most 8 MiB |
| `prometheus_timeout` | 10 s | provider `request_timeout` |
| `max_prometheus_concurrency` | 4 | 32 |

The concurrency limit is per provider. Excess queries are rejected immediately, not queued. The whole
request, including the body read, runs under a context deadline. The response is read through a
`LimitReader` of `cap + 1`; an oversized response is an error, never a truncated JSON document.

The server does not send Prometheus's `limit` parameter: it silently truncates the series count without
a truncation flag, which would make a partial result look complete.

PromQL cost is not bounded by these limits. Subqueries (`metric[30d:1s]`) and series cardinality
(`{__name__=~".+"}`) live inside the query string and can be expensive even when range, step and point
count are small. Bounding them would require a PromQL parser, which this decision deliberately avoids.
The operator must enforce cost limits on Prometheus itself (`--query.max-samples`, `--query.timeout`,
`--query.max-concurrency`). The threat model gains "monitoring availability" as an asset.

### Redaction

Content redaction applies to the decoded Prometheus JSON with the synthetic resource `prometheus`, the
datasource namespace and name, and the Service labels. `replace` applies to every string value; `fields`
operates on the JSON structure. The same hard caps apply, and a cap breach withholds the result. Numbers
are decoded with `json.Number` so native-histogram values above 2^53 survive.

Both the policy builder and the redaction builder must resolve the exact resource `prometheus` to the
synthetic resource **before** discovery. Otherwise a cluster with the Prometheus Operator CRD would
silently map a redaction rule for `prometheus` to `monitoring.coreos.com/prometheuses`, and query
results would be returned unredacted; a deny rule would miss the synthetic half in the same way.

### Errors

- `403` from the Service fetch or the proxy call is reported as `forbidden`, following the existing
  rights-oracle precedent.
- A missing Service is `not found`, matching a deleted object between fetch and query.
- `5xx`, `3xx`, non-JSON bodies and API-server error bodies are reported as a generic upstream error.
  Only status, content type and length are logged; the body is never logged or returned.
- Prometheus error JSON (`errorType`, `error`) is returned sanitized, length-capped (2 KiB) and with
  control characters stripped. `warnings` and `infos` are capped or dropped.
- Credential-plugin failures keep the existing secret-free classification.

### Dependencies and limits

- The kubeconfig identity must be allowed to `get` Services and to `get` `services/proxy` in the
  datasource namespace. This is Kubernetes RBAC, not mcp-keel policy. A `resourceNames` restriction on
  the Service name is recommended.
- The service proxy speaks HTTP to the configured port. TLS-only endpoints, authentication proxies and
  multi-tenant backends that need a tenant header (Thanos, Mimir) are not supported in this decision.
  The API server does not verify backend certificates; metric content is untrusted input either way.
- PromQL is not filtered. The datasource grant is the data boundary: an allowed datasource is readable in
  full. The server bounds endpoints, transport, cost and output, not query semantics.
- No tool evaluates `services/proxy:get`; a grant for it neither enables the Prometheus tools nor is
  implied by them. A future generic proxy tool is a separate capability decision.

### Invariant 6 exception

Invariant 6 requires one canonical form for policy matching and the API call. For Kubernetes resources
that remains unchanged. Synthetic capabilities name an operation whose wire mapping is fixed in the tool:
the agent cannot supply a resource, path, service, port or verb. The mapping `prometheus:query` →
`services/{name}:{port}/proxy/api/v1/query` is total and constant, so the bypass the invariant prevents
(alternate spellings of the same object) cannot occur. This exception is recorded in `AGENTS.md`.

## Consequences

- Agents get metrics through the same policy, logging and redaction pipeline as Kubernetes objects.
- The policy vocabulary grows by two resource-specific verbs; documentation and validation must state
  that verbs are resource-dependent.
- `list_configured_rules` shows `prometheus:query` and `prometheus:range` and the datasource **names**
  (the policy `name` dimension and the required `datasource` input), but never namespace, service or port.
  `policy_read` therefore additionally discloses the names of datasources that no `names` filter lists;
  `list_clusters` is unchanged.
- The service proxy is an implementation detail. A future direct-URL transport can be added behind the
  same capabilities without changing the policy contract.
- The threat model gains an outbound request path to a fixed API-server endpoint, a new data source
  whose label values may contain sensitive information, and the monitoring-availability asset.
