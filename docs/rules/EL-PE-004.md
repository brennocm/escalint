# EL-PE-004 — Attach a managed policy to its own user

| | |
| --- | --- |
| Severity | critical (critical when the edge is on a path to Tier 0) |
| Category | self-escalation |
| Status | stable |
| Edge | `modify_permissions` |
| Required actions | `iam:AttachUserPolicy` |
| pathfinding.cloud | [iam-008](https://pathfinding.cloud/paths/aws/iam-008) |

## Description

The principal can change its own permissions. Nothing else is needed to become an administrator of the account.

Prerequisites:

- the actor is a user

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `iam:AttachUserPolicy` on itself (or on a policy/group it already uses) with an administrative policy document.
2. The new permissions apply immediately: the principal is now an effective administrator.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:AttachUserPolicy"
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
        "iam:AttachUserPolicy"
      ],
      "Resource": "arn:aws:iam::111111111111:role/app-workers/*"
    }
  ]
}
```

## Remediation

Remove the action from the principal's policies, scope its Resource to other entities, or add a permissions boundary that denies it. A condition on iam:PolicyARN can limit which policies may be attached.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-008](https://pathfinding.cloud/paths/aws/iam-008)
