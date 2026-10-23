# 0020 — Collector: internal package of the main module

Status: Accepted

## Context

`escalint collect` needs the AWS SDK for Go v2 (about 20 modules). The rest
of escalint never talks to the network. A separate module would keep the
analysis dependency graph small; an internal package keeps one binary and
one release.

## Decision

- The collector is `internal/collect` in the main module, used only by the
  `collect` command. Analysis packages never import it (enforced by
  review; nothing in `internal/engine` or below imports the SDK).
- Every AWS call goes through small interfaces (`api.go`). Tests use fakes;
  no LocalStack.
- Only `List*`, `Get*`, `Describe*`, `BatchGet*` and, with
  `--assume-roles`, `sts:AssumeRole`. A test parses `api.go` and fails if an
  operation is not read-only or if `docs/collector-policy.json` grants more
  or less than the operations used.
- Policy documents are URL-decoded (`url.PathUnescape`, which keeps `+`)
  and stored as JSON objects, so SARIF can point at statement lines.
- Only access key statuses are stored, never key IDs; temporary credentials
  from `--assume-roles` live in memory for 15 minutes.
- SDK retries use adaptive mode with up to 10 attempts.

## Alternatives considered

- *Separate module `collector/`:* a second release artifact and version
  matrix for little gain; `go build` only links what the binary uses.
- *Shell out to the AWS CLI:* an extra runtime dependency and no control
  over pagination and retries.

## Consequences

- The binary is larger (about 21 MB); analysis stays offline.
- Verifying against a real account (pathfinding-labs ground truth) is a
  manual, opt-in procedure documented in `docs/collector.md`.
