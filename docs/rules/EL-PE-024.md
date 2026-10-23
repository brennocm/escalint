# EL-PE-024 — Pass a role to a new CodeBuild project

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | new-passrole |
| Status | stable |
| Edge | `passrole_compute` |
| Required actions | `iam:PassRole`, `codebuild:CreateProject`, `codebuild:StartBuild` |
| pathfinding.cloud | [codebuild-001](https://pathfinding.cloud/paths/aws/codebuild-001) |

## Description

The principal can create a compute resource and give it a role it does not hold. Whatever runs on that resource gets the role's permissions.

Prerequisites:

- the role trusts codebuild.amazonaws.com

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal creates a new resource (`codebuild:CreateProject`, `codebuild:StartBuild`) and passes a privileged role that trusts `codebuild.amazonaws.com`.
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
        "codebuild:CreateProject",
        "codebuild:StartBuild"
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
          "iam:PassedToService": "codebuild.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "codebuild:CreateProject",
        "codebuild:StartBuild"
      ],
      "Resource": "*"
    }
  ]
}
```

## Remediation

Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "codebuild.amazonaws.com"}} only for those roles.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- https://cwe.mitre.org/data/definitions/266.html
- pathfinding.cloud: [codebuild-001](https://pathfinding.cloud/paths/aws/codebuild-001)
