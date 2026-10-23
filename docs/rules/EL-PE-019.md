# EL-PE-019 — Put an inline policy on a user and create its access key

| | |
| --- | --- |
| Severity | critical (critical when the edge is on a path to Tier 0) |
| Category | principal-access |
| Status | stable |
| Edge | `modify_permissions` |
| Required actions | `iam:PutUserPolicy`, `iam:CreateAccessKey` |
| pathfinding.cloud | [iam-018](https://pathfinding.cloud/paths/aws/iam-018) |

## Description

The principal can raise the permissions of another principal and then act as it, turning a partial privilege into administrator access.

Prerequisites:

- the actor can create credentials for the user

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal grants administrative permissions to a principal it can become (`iam:PutUserPolicy`).
2. It becomes that principal (`iam:CreateAccessKey`) and acts as an administrator.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:PutUserPolicy",
        "iam:CreateAccessKey"
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
        "iam:CreateAccessKey"
      ],
      "Resource": "arn:aws:iam::111111111111:role/team-a/*"
    }
  ]
}
```

## Remediation

Remove the permission-management action on other principals, or deny it in a permissions boundary; also review how the caller can act as the target.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-018](https://pathfinding.cloud/paths/aws/iam-018)
