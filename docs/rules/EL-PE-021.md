# EL-PE-021 — Pass a role to a new EC2 instance

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | new-passrole |
| Status | stable |
| Edge | `passrole_compute` |
| Required actions | `iam:PassRole`, `ec2:RunInstances` |
| pathfinding.cloud | [ec2-001](https://pathfinding.cloud/paths/aws/ec2-001) |

## Description

The principal can create a compute resource and give it a role it does not hold. Whatever runs on that resource gets the role's permissions.

Prerequisites:

- the role trusts ec2.amazonaws.com
- the role is in an instance profile

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal creates a new resource (`ec2:RunInstances`) and passes a privileged role that trusts `ec2.amazonaws.com`.
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
        "ec2:RunInstances"
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
          "iam:PassedToService": "ec2.amazonaws.com"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

## Remediation

Scope iam:PassRole to the roles the caller must pass and add "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}} only for those roles.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
- https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RunInstances.html
- https://cwe.mitre.org/data/definitions/266.html
- pathfinding.cloud: [ec2-001](https://pathfinding.cloud/paths/aws/ec2-001)
