# 0012 — Action catalog generated from the AWS service reference

Status: Accepted

## Context

The engine needs to expand action wildcards (`iam:Put*`), classify actions
(permission management, write, list, read, tagging) and validate the actions
named by rules. AWS publishes this information as machine-readable JSON, the
service reference (`https://servicereference.us-east-1.amazonaws.com/`).

## Decision

- `tools/gen-catalog` (run by `go generate ./internal/catalog/`, i.e.
  `make gen`) downloads the index and every service document, keeps only the
  fields the engine uses — service prefix, schema version, modification time,
  action names, access annotations, authorized resource types and resource
  ARN formats — and writes `internal/catalog/data/catalog.json.gz`.
- The file is versioned and embedded; **scans never download anything**.
- Output is deterministic (sorted lists, gzip without name or time, fixed
  compression level): the same reference gives the same bytes.
- Access level is one value derived from the annotations with fixed
  precedence: permission management, tagging only, write, list, otherwise read.
- The tool follows service URLs only on the scheme and host of the index,
  accepts an HTTPS index on the official host only, validates prefixes and
  action names, rejects duplicates and caps response sizes.
- `internal/catalog` decodes the embedded file once (`sync.OnceValues`) and
  offers case-insensitive lookup and wildcard expansion.
- A monthly workflow (Phase 14) regenerates the file and opens a PR, so new
  services and actions are reviewed, not pulled silently.

## Alternatives considered

- *Parse the HTML Service Authorization Reference:* fragile, no annotations.
- *Download at scan time:* breaks the offline guarantee and makes results
  depend on when the scan ran.
- *Vendor a third-party list (policy_sentry, iam-dataset):* extra dependency
  and lag behind AWS.

## Consequences

- First generation (2026-10-23): 458 services, 22,316 actions, 211 KB.
- Decoding costs about 50 ms once per process.
- The annotations are AWS's, not ours: `iam:PassRole` and
  `iam:CreateAccessKey` are Write, which led to the Tier 2 amendment in ADR 0008.
- Policies may name actions the catalog does not know (new or misspelled);
  matching still works on the raw strings, and rules validate their own
  actions against the catalog in tests.
