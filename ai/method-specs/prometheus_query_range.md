# prometheus_query_range

## Purpose

Evaluate a PromQL expression over a time range against one configured Prometheus datasource. The tool
always targets the fixed endpoint `GET /api/v1/query_range` through the Kubernetes service proxy; it
never accepts a URL, path, service, port or resource identifier (ADR 0017).

## Inputs

| Field       | Type   | Required | Notes                                                             |
|-------------|--------|----------|-------------------------------------------------------------------|
| provider    | string | yes      | Logical provider name.                                            |
| context     | string | yes      | Kubeconfig context; must match the provider's `contexts`.         |
| datasource  | string | yes      | Configured datasource name (unique per provider).                 |
| query       | string | yes      | PromQL expression; control characters rejected, length cap.       |
| start       | string | yes      | RFC 3339 start timestamp (inclusive).                             |
| end         | string | yes      | RFC 3339 end timestamp (inclusive); must not precede `start`.     |
| step        | string | yes      | Positive Go duration (`15s`, `1m`); point count is bounded.       |

There is no `timeout`, `stats`, `lookback_delta`, `limit`, `max_series`, `url`, `path` or `method` input.

## Required capability

`prometheus:range` — the synthetic resource `prometheus` with verb `range`. The grant must name the
resource explicitly: `*:get` never matches it and `*:range` is rejected at configuration load. A `deny`
rule with `prometheus:*` or a scope-only deny covers it. `prometheus:query` does not imply
`prometheus:range`.

## Kubernetes API call(s)

- `GET` the configured Service (bounded) to confirm existence, validate the port and obtain the labels
  for the final decision. The Service object is never returned.
- `GET /api/v1/namespaces/{namespace}/services/{service}:{port}/proxy/api/v1/query_range` with the
  encoded `query`, `start`, `end`, `step` and a server-set `timeout`.

The tool never performs discovery: the synthetic resource is resolved from configuration, not from the
cluster.

## Authorization

1. Resolve the provider and context; the context must match the provider's `contexts`.
2. Resolve the datasource from configuration; an unknown name is a configuration error.
3. Validate the arguments (`query`, `start`, `end`, `step`, length, range, point count).
4. Policy-only pre-check with the known dimensions: a matching scope-only `deny` rule, or the absence of
   a granting `allow` rule, denies as "not found" **without** an API call.
5. Fetch the Service object.
6. Full authorization with the Service labels, the datasource name, the datasource namespace and the
   namespace marker (if enabled); the first applicable rule wins.
7. On deny, report "not found"; otherwise query Prometheus, redact and return the envelope.

`names` filters match the **datasource name**; `labels` filters match the **Service labels**. A denied,
label-excluded, marker-protected or missing Service is reported exactly like a non-existent object.

## Behavior / limits

- `query` is limited to `server.max_prometheus_query_length` (default 8 KiB, hard max 64 KiB).
- `end - start` is limited by `server.max_prometheus_query_range` (default 24 h, hard max 7 d).
- The point count `(end - start) / step + 1` is limited by `server.max_prometheus_query_points`
  (default and hard max 11000).
- The server sets the Prometheus `timeout` parameter; the agent cannot raise it. The default is 10 s and
  the hard bound is the provider's `request_timeout`.
- The response body is capped by `server.max_prometheus_response_bytes` (default 1 MiB, at most
  `server.max_response_bytes` and 8 MiB). An oversized response is an error, never a partial JSON
  document; Prometheus's `limit` parameter is not used because it truncates silently.
- Per provider, at most `server.max_prometheus_concurrency` queries run at once (default 4). Excess
  requests are rejected immediately, not queued.
- Only `2xx` responses with `application/json` are accepted. Redirects are errors and are never followed.
- If the provider configures `redactions`, they apply to the decoded JSON with the synthetic resource
  `prometheus`, the datasource namespace and name, and the Service labels (ADR 0015).
- Response envelope: `{provider, context, datasource, resultType, result, warnings?, infos?}`.

Subqueries and series cardinality are not bounded by the server; they are a documented residual risk and
must be limited on the Prometheus side (ADR 0017).

## Input validation

- `provider`, `context` and `datasource` are matched against the configuration; unknown values are
  rejected (`unknown datasource` is a configuration error, not an object-existence oracle).
- `query` must be non-empty, must not contain control characters and must fit the length cap.
- `start` and `end` must be strict RFC 3339 timestamps and `end >= start`.
- `step` must be a positive Go duration; a zero or negative value is a validation error.
- Fields outside the schema (for example `timeout` or `stats`) are rejected as unknown input.

## Errors

- `unknown datasource` — the name is not configured for this provider.
- `not found` — the Service does not exist, or the request was denied (indistinguishable).
- `forbidden` (with HTTP status) — the kubeconfig identity lacks `get` on Services or `services/proxy`.
- `query failed (invalid)` — Prometheus rejected the expression or range; the sanitized
  `errorType`/`error` is included, length-capped and stripped of control characters.
- `query failed (timeout)` — the server-side deadline expired.
- `query failed (response too large)` — the response exceeded `max_prometheus_response_bytes`; narrow the
  query or range.
- `query failed (upstream)` — a `3xx`, `5xx`, non-JSON or API-server error; the body is never returned.
- `cluster authentication failed` — a kubeconfig exec credential plugin could not provide credentials.
