# EL-PE-002 — Put an inline policy on its own role

| | |
| --- | --- |
| Severity | critical (critical when the edge is on a path to Tier 0) |
| Category | self-escalation |
| Status | stable |
| Edge | `modify_permissions` |
| Required actions | `iam:PutRolePolicy` |
| pathfinding.cloud | [iam-005](https://pathfinding.cloud/paths/aws/iam-005) |

## Description

The principal can change its own permissions. Nothing else is needed to become an administrator of the account.

Prerequisites:

- the actor is a role allowed iam:PutRolePolicy on its own ARN

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `iam:PutRolePolicy` on itself (or on a policy/group it already uses) with an administrative policy document.
2. The new permissions apply immediately: the principal is now an effective administrator.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:PutRolePolicy"
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
        "iam:PutRolePolicy"
      ],
      "Resource": "arn:aws:iam::111111111111:role/app-workers/*"
    }
  ]
}
```

## Remediation

Remove iam:PutRolePolicy from the role's policies, or scope its Resource to roles other than itself and add a permissions boundary that denies it.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-005](https://pathfinding.cloud/paths/aws/iam-005)
