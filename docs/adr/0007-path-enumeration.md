# 0007 — Path enumeration: k shortest simple paths with a depth limit

Status: Accepted

## Context

A principal may reach admin in many ways. Listing every simple path is
exponential; listing only the shortest hides alternatives that a fix of the
shortest path leaves open.

## Decision

- For every source (users, roles, external accounts, federated providers and
  "any principal" that are not already Tier 0) enumerate up to **k = 3**
  shortest simple paths to any tier0 sink with **Yen's algorithm** on hop
  counts, with a **depth limit of 6** edges (both configurable).
- A reverse breadth-first search from the sinks gives every node's distance
  to a sink once; searches prune nodes that cannot finish within the budget.
- Ties are deterministic: neighbors are visited by target ID then edge ID,
  and candidate paths are ordered by length then their edge ID sequence.
- Structural (`member_of`) and latent edges are never part of a path.

## Alternatives considered

- *All simple paths:* exponential; unusable at 10k principals.
- *Shortest path only:* the fix plan could cut it and leave the second path.
- *Weighted paths (conditional = more expensive):* hides the fact that a
  conditional path is still a path; status is reported per path instead.

## Consequences

- Benchmarks on random graphs: 1k nodes 6 ms, 10k 35 ms, 50k 255 ms.
- Paths longer than the limit are not reported; the limit is shown in the
  output so users can raise it.
