# 0003 — Contract source of truth: JSON Schema → Go (validation) and TS (generation)

Status: Accepted

## Context

`analysis.json` is the contract between the Go engine and the web UI, and a
public output format. Go structs, TypeScript types and documentation must
not drift apart.

## Decision

- `schema/analysis.v1.schema.json` (JSON Schema draft 2020-12, written by
  hand) is the source of truth. `additionalProperties: false` everywhere so
  unknown fields fail validation.
- Go: `internal/contract` holds hand-written structs; a test validates every
  golden `analysis.json` against the schema, so a field added to the structs
  but not to the schema (or the reverse) fails CI.
- TypeScript: `web/src/contract/analysis.ts` is generated from the schema
  (`pnpm gen:contract`); `make gen-check` regenerates and fails on a diff.
- `schema_version` is `"1"`. An incompatible change gets a new version and
  a new schema file; the UI refuses versions it does not know.
- Output is byte-for-byte deterministic: lists sorted, maps serialized with
  sorted keys, `stats.duration_ms` omitted with `--deterministic`.

Changes from the skeleton of project.md §3.3, recorded in
docs/research.md §9: edges gain `latent`, `actor`, `prerequisites_unverified`
and `detection`; nodes gain `tier_conditional` and `service_linked`;
findings gain `edge_id`, `node_id`, `location`; `suppressed` is an object or
null with top-level `suppressions[]`; `rules[]` carries rule metadata with
ATT&CK techniques so the UI never needs a second source. The per-edge
`evaluations` trace map is not part of v1: `evidence[]` already names the
deciding statements, and full traces stay available through the CLI.

## Alternatives considered

- *Go structs as source, schema generated:* the schema would follow Go
  quirks (omitempty, pointer nullability) instead of being designed.
- *Protobuf:* a toolchain for a single JSON document read by a browser.

## Consequences

- Adding a field means editing the schema, the Go struct, and regenerating
  the TypeScript types; CI catches any forgotten step.
