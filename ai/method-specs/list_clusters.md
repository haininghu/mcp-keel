# list_clusters

## Purpose

Let the agent discover which `provider`/`context` pairs it may target, so it can form valid requests
without guessing context names. It reports the configured patterns and the **concrete** context names the
kubeconfig currently provides.

## Inputs

None.

## Required capability

The provider must set `policy_read: true`. Providers without it are omitted entirely.

## Kubernetes API call(s)

None — the context names come from the kubeconfig referenced by the provider; no cluster API is called.

## Authorization

1. Iterate the configured providers.
2. Include a provider only when `policy_read: true`.
3. For each, read the provider's kubeconfig and emit:
   - `context_patterns`: the configured `contexts` globs, as written;
   - `contexts`: the concrete kubeconfig context names that match those patterns, sorted.
4. Never emit kubeconfig contents, server URLs, credentials or certificate data.

## Output

```json
{
  "providers": [
    {
      "provider": "test-clusters",
      "context_patterns": ["*test*", "dev-play-cluster"],
      "contexts": ["dev-play-cluster", "test-a", "test-b"]
    }
  ]
}
```

## Behavior / limits

- Output is sorted by provider name, then context name.
- `contexts` lists only contexts that exist in the kubeconfig and match the patterns; a pattern with no
  match contributes nothing. If the kubeconfig cannot be read, `contexts` is empty for that provider and
  the failure is logged server-side only.
- This tool is an infrastructure-enumeration surface; it is deliberately gated by `policy_read`.

## Errors

None — an empty list is returned when no provider opts in.
