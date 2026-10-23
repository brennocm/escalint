# 0023 — Strict JSON decoding for untrusted input

Status: Accepted

## Context

Snapshots and the policies inside them are controlled by whoever can change
the AWS account, and a snapshot file can be edited after collection. If
escalint reads a document differently from AWS (a *parser differential*), an
attacker can hide a path: escalint sees a Deny where AWS applies an Allow.

`encoding/json` (v1) has three such behaviors:

- duplicate object keys are accepted and the last one wins;
- struct field names match case-insensitively (`"arn"` fills `Arn`);
- `null` decodes to the zero value, so `"Condition": null` silently becomes
  "no condition".

## Decision

- `internal/jsonx.Check` walks the raw tokens of every policy document and
  snapshot before decoding: invalid JSON, trailing data, duplicate keys and
  nesting deeper than the limit are errors with a path.
- Policy documents are decoded member by member with exact element names;
  unknown elements, `null` where a value is required, and empty lists
  (`"NotAction": []` would mean "every action") are rejected.
- Snapshot wire types are decoded with `encoding/json/v2`, which matches
  names case-sensitively and rejects duplicates. Unknown fields are still
  ignored, so new AWS response fields do not break loading.
- Paths in error messages escape keys that are not printable ASCII, and every
  CLI error goes through `internal/termsafe.Line`, so snapshot content cannot
  inject terminal escape sequences or bidirectional overrides.
- A policy that fails these checks is kept with a nil document and reported
  as `EL-PARSE-001`; the rest of the snapshot is still analyzed.

## Alternatives considered

- *Only `encoding/json/v2` everywhere:* it covers duplicates and case, but
  `jsonx` gives errors with document paths, our own depth limit and the same
  checks for the raw policy text that the parser then reads member by member.
- *Lenient parsing with warnings:* a lenient reader is exactly what a parser
  differential exploits.

## Consequences

- Malformed or tampered input produces findings instead of silently changing
  results.
- Policies that AWS itself would reject never reach the evaluator.
- Regression tests named `TestRegression*` pin each case found in review.
