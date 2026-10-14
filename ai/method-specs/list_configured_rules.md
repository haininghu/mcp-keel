# list_configured_rules

## Purpose

Expose the configured access rules for providers that opt in, so the agent can orient itself and an
operator can audit. It reports **configuration only**, never effective access or live object state.

## Inputs

None.

## Required capability

The provider must set `policy_read: true`. Providers without it are omitted entirely.

## Kubernetes API call(s)

None.

## Authorization

1. Iterate the configured providers.
2. Include a provider only when `policy_read: true`.
3. Emit each rule's scope (`namespaces`), `effect` and configured capabilities with their filters.
4. Never emit effective access, object state, tokens or kubeconfig contents. The `policy_read` flag and
   `kubeconfig` paths are configuration plumbing and are not part of the output either.

## Behavior / limits

- Output is sorted by provider name; rule order within a provider is preserved.
- The response contains only configuration as written, not the result of canonicalisation.

## Errors

None — an empty list is returned when no provider opts in.
