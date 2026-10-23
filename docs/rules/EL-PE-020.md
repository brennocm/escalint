# EL-PE-020 — Modify a role's permissions and rewrite its trust

| | |
| --- | --- |
| Severity | critical (critical when the edge is on a path to Tier 0) |
| Category | principal-access |
| Status | stable |
| Edge | `modify_permissions` |
| Required actions | `iam:AttachRolePolicy`, `iam:CreatePolicyVersion`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy` |
| pathfinding.cloud | [iam-019](https://pathfinding.cloud/paths/aws/iam-019), [iam-020](https://pathfinding.cloud/paths/aws/iam-020), [iam-021](https://pathfinding.cloud/paths/aws/iam-021) |

## Description

The principal can raise the permissions of another principal and then act as it, turning a partial privilege into administrator access.

Prerequisites:

- one of the permission actions plus iam:UpdateAssumeRolePolicy on the role

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal grants administrative permissions to a principal it can become (`iam:AttachRolePolicy`).
2. It becomes that principal (`iam:CreatePolicyVersion`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`) and acts as an administrator.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:PutRolePolicy",
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
      "Action": [],
      "Resource": "arn:aws:iam::111111111111:role/team-a/*"
    }
  ]
}
```

## Remediation

Remove the permission-management action on other principals, or deny it in a permissions boundary; also review how the caller can act as the target.

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html
- https://cwe.mitre.org/data/definitions/269.html
- pathfinding.cloud: [iam-019](https://pathfinding.cloud/paths/aws/iam-019), [iam-020](https://pathfinding.cloud/paths/aws/iam-020), [iam-021](https://pathfinding.cloud/paths/aws/iam-021)
