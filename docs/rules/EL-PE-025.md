# EL-PE-025 — Pass a role to a new Glue job

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | new-passrole |
| Status | stable |
| Edge | `passrole_compute` |
| Required actions | `iam:PassRole`, `glue:CreateJob`, `glue:StartJobRun` |
| pathfinding.cloud | [glue-003](https://pathfinding.cloud/paths/aws/glue-003) |

## Description

The principal can create a compute resource and give it a role it does not hold. Whatever runs on that resource gets the role's permissions.

Prerequisites:

- the role trusts glue.amazonaws.com

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal creates a new resource (`glue:CreateJob`, `glue:StartJobRun`) and passes a privileged role that trusts `glue.amazonaws.com`.
2. Code it controls runs with the role's credentials.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:PassRole",
        "glue:CreateJob",
        "glue:StartJobRun"
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
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111111111111:role/app-runtime-*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "glue.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "glue:CreateJob",
        "glue:StartJobRun"
      ],
      "Resource": "*"
    }
  ]
}
```

## Remediation

Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "glue.amazonaws.com"}} only for those roles.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- https://cwe.mitre.org/data/definitions/266.html
- pathfinding.cloud: [glue-003](https://pathfinding.cloud/paths/aws/glue-003)
