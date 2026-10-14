# list_clusters

## Purpose

Let the agent discover which `provider`/`context` pairs it may target, so it can form valid requests
without guessing context names.

## Inputs

None.

## Required capability

The provider must set `policy_read: true`. Providers without it are omitted entirely.

## Kubernetes API call(s)

None — the provider and context names come from the configuration. The kubeconfig is not read to enumerate
contexts beyond what the provider already declares.

## Authorization

1. Iterate the configured providers.
2. Include a provider only when `policy_read: true`.
3. For each, emit the provider name and its configured `contexts` patterns.
4. Optionally, when the kubeconfig is available, emit the concrete context names that match those patterns.
   Never emit kubeconfig contents, server URLs, credentials or certificate data.

## Behavior / limits

- Output is sorted by provider name, then context name.
- This tool is an infrastructure-enumeration surface; it is deliberately gated by `policy_read`.

## Errors

None — an empty list is returned when no provider opts in.
