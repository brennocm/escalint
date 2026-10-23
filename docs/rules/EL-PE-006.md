# EL-PE-006 — Attach a managed policy to its own group

| | |
| --- | --- |
| Severity | critical (critical when the edge is on a path to Tier 0) |
| Category | self-escalation |
| Status | stable |
| Edge | `modify_permissions` |
| Required actions | `iam:AttachGroupPolicy` |
| pathfinding.cloud | [iam-010](https://pathfinding.cloud/paths/aws/iam-010) |

## Description

The principal can change its own permissions. Nothing else is needed to become an administrator of the account.

Prerequisites:

- the actor is a member of the group

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `iam:AttachGroupPolicy` on itself (or on a policy/group it already uses) with an administrative policy document.
2. The new permissions apply immediately: the principal is now an effective administrator.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:AttachGroupPolicy"
      ],
      "Resource": "arn:aws:iam::111111111111:group/developers"
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
        "iam:AttachGroupPolicy"
      ],
      "Resource": "arn:aws:iam::111111111111:role/app-workers/*"
    }
  ]
}
```

## Remediation

Remove the action from the principal's policies, scope its Resource to other entities, or add a permissions boundary that denies it.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-010](https://pathfinding.cloud/paths/aws/iam-010)
