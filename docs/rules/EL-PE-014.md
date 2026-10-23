# EL-PE-014 — Assume a more privileged role

| | |
| --- | --- |
| Severity | medium (critical when the edge is on a path to Tier 0) |
| Category | principal-access |
| Status | stable |
| Edge | `assume` |
| Required actions | `sts:AssumeRole` |
| pathfinding.cloud | [sts-001](https://pathfinding.cloud/paths/aws/sts-001) |

## Description

The principal can assume a role whose permissions exceed its own.

Prerequisites:

- the role's trust policy accepts the actor (docs/research.md §2.4)

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `sts:AssumeRole` on a role whose trust policy accepts it.
2. It acts with the role's permissions.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Fixed example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:role/deployer"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

## Remediation

Name only the principals that need the role in its trust policy, add conditions (sts:ExternalId, aws:PrincipalOrgID, MFA) and scope sts:AssumeRole in identity policies to specific role ARNs.

## References

- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [sts-001](https://pathfinding.cloud/paths/aws/sts-001)
