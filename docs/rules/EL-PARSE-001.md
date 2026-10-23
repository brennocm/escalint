# EL-PARSE-001 — Policy document could not be parsed

| | |
| --- | --- |
| Severity | info |
| Category | parse |
| Status | stable |

## Description

A policy in the snapshot is not valid IAM policy JSON: invalid JSON, a
duplicate key, an unknown element, `null` where a value is required, an
empty list, `NotPrincipal` with `Allow`, and similar cases (ADR 0023). The
finding names the policy and the location inside it.

## Why it matters

escalint never guesses what a broken policy means. The policy contributes
nothing to the analysis, so an escalation path that depends on one of its
`Allow` statements may be missing, and a `Deny` in it is not applied. AWS
rejects most of these documents, so a finding usually means the snapshot was
edited or produced by a tool with a bug.

## Attack chain

Not an attack by itself. A tampered snapshot could try to hide a path with
an ambiguous document (for example two `Effect` keys); escalint reports it
instead of reading it differently from AWS.

## Vulnerable example

```json
{"Version": "2012-10-17", "Statement": {"Effect": "Deny", "Effect": "Allow", "Action": "*", "Resource": "*"}}
```

## Fixed example

```json
{"Version": "2012-10-17", "Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}}
```

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
- docs/adr/0023-strict-json-for-untrusted-input.md
