# EL-PE-029 — Run a command on an instance that has a role

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | existing-passrole |
| Status | experimental (runs with `--experimental`) |
| Edge | `update_code` |
| Required actions | `ssm:SendCommand` |
| pathfinding.cloud | [ssm-002](https://pathfinding.cloud/paths/aws/ssm-002) |

## Description

The principal can change what an existing resource runs, and that resource already has a role. The new code runs with the role's permissions.

Prerequisites:

- an SSM-managed EC2 instance runs with the role

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal changes what an existing resource runs (`ssm:SendCommand`).
2. The resource executes that code with its role's credentials.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:SendCommand"
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
        "ssm:SendCommand"
      ],
      "Resource": "arn:aws:*:*:111111111111:*team-a*"
    }
  ]
}
```

## Remediation

Restrict ssm:SendCommand to the resources the caller owns; separate deployment roles from runtime roles.

## References

- https://cwe.mitre.org/data/definitions/266.html
- pathfinding.cloud: [ssm-002](https://pathfinding.cloud/paths/aws/ssm-002)
