# logs

## Purpose

Fetch bounded log text for one pod, under policy. The tool always reads the canonical subresource
`pods/log` with verb `get` (matching Kubernetes RBAC); it never accepts a resource identifier, so no other
subresource (for example `services/proxy`) is reachable.

## Inputs

| Field        | Type   | Required | Notes                                                          |
|--------------|--------|----------|----------------------------------------------------------------|
| provider     | string | yes      | Logical provider name.                                         |
| context      | string | yes      | Kubeconfig context; must match the provider's `contexts`.      |
| namespace    | string | yes      | Namespace of the pod; `logs` is namespaced only.               |
| pod          | string | yes      | Pod name.                                                      |
| container    | string | no       | Required when the pod has more than one container.             |
| previous     | bool   | no       | Read the previous container instance (default `false`).        |
| timestamps   | bool   | no       | Prefix each line with an RFC 3339 timestamp (default `false`). |
| tailLines    | int    | no       | Number of trailing lines; clamped to `server.max_log_lines`.   |
| sinceSeconds | int    | no       | Relative time window in seconds; must be `>= 0`.               |

There is no `follow` input and no `resource` input: the read is a bounded single GET, never a stream.

## Required capability

`pods/log:get` — the canonical subresource `pods/log` with verb `get`. The agent must grant it explicitly:
an `allow` `*` never matches subresources, so a wildcard never grants logs. A `deny` rule with `resource: "*"`
or `verb: "*"` does cover them.

## Kubernetes API call(s)

- Discovery to canonicalise the fixed resource `pods/log` (ADR 0012).
- `GET` the pod object. Log text carries no labels, so the pod supplies the labels, the name and the
  container list for the final decision; the pod object is never returned.
- `GET` the pod log with `container`, `previous`, `timestamps`, `tailLines`, `sinceSeconds` and
  `limitBytes = server.max_log_bytes + 1` (the extra byte detects truncation).

## Authorization

1. Resolve the provider and context; the context must match the provider's `contexts`.
2. Canonicalise the fixed resource `pods/log` (fail-closed if the cluster does not expose it).
3. Validate the arguments (`namespace`, `pod`, `container`, bounds).
4. Policy-only pre-check ignoring label filters: a matching scope-only `deny` rule, or the absence of a
   granting `allow` rule, denies as "not found" **without** an API call.
5. Fetch the pod object.
6. Full authorization with the pod's labels, name and the namespace marker (if enabled); the first
   applicable rule wins (`allow` grants, `deny` denies).
7. On deny, report "not found"; otherwise fetch the log, redact it and return the envelope.

A denied, label-excluded, marker-protected or missing pod is reported exactly like a non-existent one.

## Behavior / limits

- `container` is required when the pod has more than one container; a single-container pod defaults to it.
- `tailLines` defaults to and is capped by `server.max_log_lines` (default 500, hard max 10000).
- `server.max_log_bytes` (default 262144, hard max 16 MiB) caps the returned bytes and must be less than
  `server.max_response_bytes`. When the extra byte is returned, the content is cut and `truncated: true`.
- There is no `follow`: the tool never streams and never waits for new lines. Mutating and streaming verbs
  remain out of scope.
- Log text is arbitrary application output. If the provider configures `redactions`, only the `replace`
  phase applies to it (ADR 0015); `fields` has no target in text.
- Response envelope: `{provider, context, resource: "pods/log", namespace, pod, container, content,
  truncated}` (see `output.md`).

## Input validation

- `provider` and `context` are matched against the configuration and the kubeconfig; unknown values are
  rejected.
- `namespace` and `pod` are validated as Kubernetes names (DNS label/subdomain) and length-bounded.
- `container` is validated as a container name; a missing `container` on a multi-container pod is a
  validation error.
- `tailLines` and `sinceSeconds` must not be negative.
- Control characters are rejected to prevent log injection.

## Errors

- `not found` — the pod does not exist, or the request was denied (indistinguishable).
- `forbidden` (with HTTP status) — the kubeconfig identity lacks RBAC permission for `pods/log` or for the
  pod fetch (`pods`).
- `unknown resource: pods/log` — the cluster does not expose the `pods/log` subresource.
- `cluster authentication failed` — a kubeconfig exec credential plugin could not provide credentials (for
  example an expired `gcloud` login). The message names the plugin and suggests re-authenticating; it never
  includes plugin output.
- Validation errors — a missing `namespace`/`pod`, an invalid `container` name, a missing `container` on a
  multi-container pod, or a negative `tailLines`/`sinceSeconds`.
