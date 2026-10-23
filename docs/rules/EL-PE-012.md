# EL-PE-012 — Change another user's console password

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | principal-access |
| Status | stable |
| Edge | `credential` |
| Required actions | `iam:UpdateLoginProfile` |
| pathfinding.cloud | [iam-006](https://pathfinding.cloud/paths/aws/iam-006) |

## Description

The principal can take over another IAM principal by acting on its credentials, trust policy or group membership.

Prerequisites:

- the target user has a console password
- MFA on the target may still block console use

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal calls `iam:UpdateLoginProfile` for `arn:aws:iam::111111111111:user/target`.
2. It signs in or calls AWS as that user, with the user's permissions.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:UpdateLoginProfile"
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
        "iam:UpdateLoginProfile"
      ],
      "Resource": "arn:aws:iam::111111111111:user/${aws:username}"
    }
  ]
}
```

## Remediation

Scope iam:UpdateLoginProfile to the caller's own user and enforce MFA for every console user.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateLoginProfile.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-006](https://pathfinding.cloud/paths/aws/iam-006)
