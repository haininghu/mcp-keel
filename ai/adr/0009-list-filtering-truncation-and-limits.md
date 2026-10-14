# 0009. List filtering, truncation and limits

## Status

Accepted.

## Context

`list` can return a large collection, span every namespace and hide items by policy. mcp-forj learned
(bug 0006, bug 0008) that an unbounded scan is a denial-of-service vector and that returning the number of
hidden items leaks information about objects the caller cannot see.

## Decision

- **Bounded scan.** A `list` fetches a bounded window (`limit` plus a small factor, and never more than
  `server.max_list_items`). If the caller's window is exhausted, the response sets `truncated: true`. There
  are no `continue` tokens in v1.
- **Item cap.** `server.max_list_items` caps the number of returned items; the tool's `limit` is clamped to
  it.
- **Object size.** A serialized object larger than `server.max_object_bytes` is truncated and flagged.
- **Per-item authorization.** Each returned item is evaluated by the ordered rules with its own namespace
  and labels (a `deny` rule that matches, or the absence of a matching `allow`, drops it). Dropped items
  are counted **server-side only**.
- **All-namespaces listing.** When `namespace` is omitted, the server first checks that `resource:list` is
  granted for at least one namespace in the provider/context, then filters every item by its namespace.
  This does **not** require a `namespaces: ["*"]` rule: per-item filtering already keeps the result safe,
  and it lets a `test-*` grant list across all namespaces while only seeing `test-*` objects.
- The response never contains the number of hidden items, and a hidden item is not distinguishable from an
  item that does not exist.

## Consequences

- Listing cannot be used to enumerate hidden objects or to force an unbounded scan.
- A caller may receive fewer items than exist without learning how many were hidden.
- Very large objects are returned truncated with an explicit flag.
