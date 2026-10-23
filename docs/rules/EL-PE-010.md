# EL-PE-010 — Rotate out and create an access key for another user

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | principal-access |
| Status | stable |
| Edge | `credential` |
| Required actions | `iam:CreateAccessKey`, `iam:DeleteAccessKey` |
| pathfinding.cloud | [iam-003](https://pathfinding.cloud/paths/aws/iam-003) |

## Description

The principal can take over another IAM principal by acting on its credentials, trust policy or group membership.

Prerequisites:

- the target is an IAM user

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `iam:CreateAccessKey` for `arn:aws:iam::111111111111:user/target`.
2. It signs in or calls AWS as that user, with the user's permissions.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey"
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
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey"
      ],
      "Resource": "arn:aws:iam::111111111111:user/${aws:username}"
    }
  ]
}
```

## Remediation

Scope iam:CreateAccessKey and iam:DeleteAccessKey to the caller's own user (arn:aws:iam::<account>:user/${aws:username}).

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-003](https://pathfinding.cloud/paths/aws/iam-003)
