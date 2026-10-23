# 0011 — SARIF locations for findings without "file:line"

Status: Accepted

## Context

SARIF consumers (GitHub code scanning) expect results anchored to a file and
line. escalint findings are about IAM entities; the only file is the
snapshot, and policy documents inside it may be JSON strings (URL-encoded
by the SDK) rather than nested objects.

## Decision

- Every result has a `logicalLocation` per entity involved (kind `user`,
  `role`, `group` or `resource`, `fullyQualifiedName` = ARN).
- When the snapshot file is known, results also get a `physicalLocation`:
  the snapshot path (relative to the working directory when possible) and
  the line of the deciding statement, found by walking the raw JSON with
  `jsontext.Decoder` and its `InputOffset`. When the document is a string,
  the line of the document value is used; when nothing matches, the line of
  the entity object; failing that, line 1.
- `partialFingerprints.escalint/v1` is the finding ID (stable across runs,
  ADR 0010), so code scanning tracks alerts across snapshots.
- Rule metadata goes to `tool.driver.rules`: full markdown `help`,
  `security-severity` (critical 9.5, high 8.0, medium 5.5, low 3.0, info
  0.0), and tags (`security`, category, `external/attack/<technique>`).

## Alternatives considered

- *Logical locations only:* GitHub drops results without a physical
  location.
- *Synthesizing one file per principal:* a fake artifact users cannot open.

## Consequences

- Alerts point at the statement to fix when the snapshot keeps documents as
  objects (the escalint collector does); otherwise at the right policy.
