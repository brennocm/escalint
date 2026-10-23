# 0010 — Stable IDs and their interaction with redaction

Status: Accepted

## Context

The UI keeps selections in URLs, the Diff view anchors layouts across two
snapshots, and SARIF results must keep identity across runs. IDs must not
change when unrelated parts of the account change, and must not leak
identifiers when output is redacted.

## Decision

- Node IDs are `n_` + the first 16 hex digits of SHA-256 over a canonical
  key: the ARN for IAM entities, `service:<name>`, `account:<id>`,
  `federated:<provider>`, `any_principal`, `tier0:<account>`.
- Edge IDs hash `from|to|kind`; path IDs hash the comma-joined edge IDs;
  finding IDs hash rule and edge.
- IDs are computed **before** redaction. `diff` therefore runs on unredacted
  analyses and redaction is applied last.
- Because unredacted IDs are hashes of ARNs, redacted output **replaces IDs
  too** with per-run pseudonyms (HMAC with a random key), otherwise a reader
  could confirm a guessed ARN by hashing it.

## Alternatives considered

- *Sequential IDs:* change whenever an entity is added.
- *Raw ARNs as IDs:* long, and leak identifiers into URLs.

## Consequences

- Two runs over the same snapshot produce identical IDs; a role keeps its ID
  until its ARN changes.
- Redacted reports cannot be diffed against each other.
