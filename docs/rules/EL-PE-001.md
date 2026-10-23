# EL-PE-001 — Create a new default version of an attached policy

| | |
| --- | --- |
| Severity | critical (critical when the edge is on a path to Tier 0) |
| Category | self-escalation |
| Status | stable |
| Edge | `modify_permissions` |
| Required actions | `iam:CreatePolicyVersion` |
| pathfinding.cloud | [iam-001](https://pathfinding.cloud/paths/aws/iam-001) |

## Description

The principal can change its own permissions. Nothing else is needed to become an administrator of the account.

Prerequisites:

- a customer managed policy is attached to the actor (directly or through a group)

Not checked: a managed policy keeps at most five versions, so on a policy
that already has five the actor also needs `iam:DeletePolicyVersion`. The
snapshot lists the versions, but escalint v1 does not use the count; the
finding may over-report in that case. A permissions boundary that would cap
the new version makes the edge `conditional`.

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `iam:CreatePolicyVersion` on itself (or on a policy/group it already uses) with an administrative policy document.
2. The new permissions apply immediately: the principal is now an effective administrator.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreatePolicyVersion"
      ],
      "Resource": "arn:aws:iam::111111111111:policy/AppPolicy"
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
        "iam:CreatePolicyVersion"
      ],
      "Resource": "arn:aws:iam::111111111111:role/app-workers/*"
    }
  ]
}
```

## Remediation

Remove iam:CreatePolicyVersion or scope it to policies that are not attached to the caller; deny it in a permissions boundary.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-001](https://pathfinding.cloud/paths/aws/iam-001)
