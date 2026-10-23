# 0022 — CloudTrail detection hints

Status: Proposed (Phase 1E checkpoint)

## Context

Static analysis tells defenders which escalation paths exist. The next
question is "if someone uses this path, what would we see?". The answer is
per step: a three-step path produces different CloudTrail events in each step,
sometimes in different accounts, and some steps produce nothing.

## Decision

- **Granularity: per edge kind, refined per rule.** Each edge carries a
  `StepDetection`: events (`eventSource`, `eventName`, management/data, key
  fields, region note, notes), blind spots, `requires_data_events` and a status
  (`verified` | `experimental`).
- **Generated, then reviewed.** `tools/gen-detect` (via `go generate`, never in
  a scan) derives candidate action → operation → event mappings from
  `Operations[].AuthorizedActions` in the embedded service reference, then
  applies `internal/detect/data/overrides.yaml` and writes
  `internal/detect/data/detect.json`. Overrides exist because the generated
  mapping is wrong or too broad in known cases:
  - `iam:PassRole` is authorized by 146 operations and produces no event of its
    own; overrides restrict it to the rule's compute operation and add a blind
    spot.
  - Lambda event names carry version suffixes (`CreateFunction20150331`,
    `UpdateFunctionCode20150331v2`) that the service reference does not list.
  - `sts:AssumeRoleWithWebIdentity` and `sts:AssumeRoleWithSAML` have no
    operation mapping in the service reference.
- **Blind spots are first-class.** They are explicit strings shown in every
  output: permissions that are not events (PassRole), data events off by default
  (Lambda `Invoke`), `readOnly` STS events lost by write-only trails, denied
  cross-account assumptions not logged in the target account, payloads omitted
  from logs (Lambda code, CloudFormation parameter values), and activity inside
  compute that never reaches CloudTrail.
- **Consistency rule (tested):** every action a rule requires is covered by an
  event or by a blind spot that names it.
- **Status:** `verified` when the event source, name and category are confirmed
  in the service's CloudTrail documentation; field paths not shown in an
  official sample stay `experimental` until a live validation run
  (opt-in, checkpoint before any real account) promotes them.

## Out of scope (v1)

- Ready-made queries (Athena, CloudTrail Lake, Sigma, SPL). A wrong query is
  worse than none; the data model keeps `eventSource`/`eventName`/fields so a
  future generator can build them (v0.2 idea).
- Reading CloudTrail to tell whether a path was used: escalint stays static and
  offline.
- D3FEND, CTID mappings, OCSF output.

## Alternatives considered

- *Hand-written catalog only:* drifts as services add operations; no way to
  notice new authorizing operations.
- *Generated only:* wrong for PassRole and Lambda, silent about blind spots.
- *Per rule only:* hides that steps of one path are logged differently.

## Consequences

- The Trace view can show visibility per step (visible / partial / blind) with
  a Detect tab; the Overview can count critical paths with blind spots.
- The catalog must be re-reviewed when the service reference changes; the
  monthly catalog workflow regenerates `detect.json` and the diff is reviewed.
