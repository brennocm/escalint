# 0015 — Layout determinism

Status: Accepted

## Context

URLs carry the camera, reports are compared over time, and visual tests
need identical pictures: the same analysis must always produce the same
layout.

## Decision

- Seeds come from the data: the force layout seeds a mulberry32 PRNG with
  the FNV-1a hash of the joined node IDs (stable IDs, ADR 0010).
- No time-based cooling: the step size shrinks with the iteration index;
  the iteration count depends only on the number of nodes.
- Iteration orders are fixed (nodes sorted by ID; edges by index).
- Groups (accounts) start on a circle in sorted order.
- Radial (Reach) and layered (Trace) layouts are closed-form plus the
  barycenter heuristic, whose ties are broken by ID.
- The Diff view lays out the union of both sides once, so a node keeps its
  position whatever side it is on.
- Camera values in URLs are rounded to two decimals.

## Consequences

- Tests assert identical output for repeated runs.
- Adding one node changes the seed, so a layout may move noticeably between
  two snapshots; the Diff view avoids that by laying out the union.
