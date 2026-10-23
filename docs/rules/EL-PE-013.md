# EL-PE-013 — Rewrite a role's trust policy

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | principal-access |
| Status | stable |
| Edge | `modify_trust` |
| Required actions | `iam:UpdateAssumeRolePolicy` |
| pathfinding.cloud | [iam-012](https://pathfinding.cloud/paths/aws/iam-012) |

## Description

The principal can take over another IAM principal by acting on its credentials, trust policy or group membership.

Prerequisites:

- the target role is not service-linked
- the actor can assume the role once the trust names it

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `iam:UpdateAssumeRolePolicy` on `arn:aws:iam::111111111111:role/target` and makes the trust name itself.
2. It calls `sts:AssumeRole` on the role and receives its credentials.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*"
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
      "Action": [
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "arn:aws:iam::111111111111:role/team-a/*"
    }
  ]
}
```

## Remediation

Restrict iam:UpdateAssumeRolePolicy to administrators, scope it to specific role ARNs, or deny it in a permissions boundary.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-012](https://pathfinding.cloud/paths/aws/iam-012)
