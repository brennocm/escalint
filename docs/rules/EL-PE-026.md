# EL-PE-026 — Pass a role to a new ECS task

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | new-passrole |
| Status | experimental (runs with `--experimental`) |
| Edge | `passrole_compute` |
| Required actions | `iam:PassRole`, `ecs:RegisterTaskDefinition`, `ecs:RunTask` |
| pathfinding.cloud | [ecs-002](https://pathfinding.cloud/paths/aws/ecs-002), [ecs-004](https://pathfinding.cloud/paths/aws/ecs-004) |

## Description

The principal can create a compute resource and give it a role it does not hold. Whatever runs on that resource gets the role's permissions.

Prerequisites:

- the role trusts ecs-tasks.amazonaws.com
- an ECS cluster exists or can be created

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal creates a new resource (`ecs:RegisterTaskDefinition`, `ecs:RunTask`) and passes a privileged role that trusts `ecs-tasks.amazonaws.com`.
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
        "ecs:RegisterTaskDefinition",
        "ecs:RunTask"
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
          "iam:PassedToService": "ecs-tasks.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecs:RegisterTaskDefinition",
        "ecs:RunTask"
      ],
      "Resource": "*"
    }
  ]
}
```

## Remediation

Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}} only for those roles.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- https://cwe.mitre.org/data/definitions/266.html
- pathfinding.cloud: [ecs-002](https://pathfinding.cloud/paths/aws/ecs-002), [ecs-004](https://pathfinding.cloud/paths/aws/ecs-004)
