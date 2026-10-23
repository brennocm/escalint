# EL-PARSE-003 — Suppression without a justification

| | |
| --- | --- |
| Severity | info |
| Category | parse |
| Status | stable |

## Description

A suppression in `.escalint.yaml` has an empty `reason`. escalint requires a
justification for every suppression: without one, the suppression is
recorded with status `unjustified`, suppresses nothing, and this finding
points at it.

## Why it matters

Suppressions hide real escalation paths from reports and CI gates. A reason
(who accepted the risk, why, and where it was discussed) keeps that decision
reviewable; an expiry date makes sure it is reviewed again.

## Attack chain

Not an attack by itself; it keeps accepted risks visible and accountable.

## Vulnerable example

```yaml
version: 1
suppressions:
  - rule: EL-TR-004
    arn: "arn:aws:iam::111111111111:role/legacy-partner"
    reason: ""
```

## Fixed example

```yaml
version: 1
suppressions:
  - rule: EL-TR-004
    arn: "arn:aws:iam::111111111111:role/legacy-partner"
    reason: "Partner integration approved by the security team (SEC-1234)"
    expires: 2027-01-31
```

## References

- https://github.com/brennocm/escalint/blob/main/docs/configuration.md
