# 0024 — Property-based testing with rapid alongside native fuzzing

Status: Accepted

## Context

The specification asks for invariants on the matcher, the evaluator and the
graph ("deny always wins", "every enumerated path is simple", "expansion is a
subset of the catalog"). Go's native fuzzing finds crashes and differential
bugs from byte inputs, but it has no generators for structured values (a
policy, a graph) and no shrinking to a minimal counterexample.

## Decision

- Keep **native fuzzing** for every parser and matcher (`Fuzz*` targets, run
  by `make fuzz` / `make fuzz-smoke` and in CI), including differential
  checks against independent oracles.
- Use **`pgregory.net/rapid` v1.3.0** for property tests over structured
  values. It is a test-only dependency: it is never linked into the binary.
- License: MPL-2.0, a file-level copyleft that applies only if we modify and
  distribute rapid's own files; using it unmodified in tests is fine.

## Alternatives considered

- *Native fuzzing only:* structured properties would need hand-written
  decoders from bytes to policies and graphs, and failures would not shrink.
- *testing/quick:* frozen, no shrinking, weak generators.
- *gopter:* larger API, less active.

## Consequences

- Property failures print a minimal counterexample and a seed to replay.
- One more module in `go.sum`, test-only.
