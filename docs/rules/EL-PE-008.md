# EL-PE-008 — Add itself to a more privileged group

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | self-escalation |
| Status | stable |
| Edge | `modify_permissions` |
| Required actions | `iam:AddUserToGroup` |
| pathfinding.cloud | [iam-013](https://pathfinding.cloud/paths/aws/iam-013) |

## Description

The principal can take over another IAM principal by acting on its credentials, trust policy or group membership.

Prerequisites:

- the actor is a user that is not yet a member

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The user calls `iam:AddUserToGroup` to join `arn:aws:iam::111111111111:group/admins`.
2. The group's policies apply to the user immediately.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:AddUserToGroup"
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
        "iam:AddUserToGroup"
      ],
      "Resource": "arn:aws:iam::111111111111:group/team-a/*"
    }
  ]
}
```

## Remediation

Scope iam:AddUserToGroup to specific groups and never allow it on groups with administrative policies.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddUserToGroup.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-013](https://pathfinding.cloud/paths/aws/iam-013)
