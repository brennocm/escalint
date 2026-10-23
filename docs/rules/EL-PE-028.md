# EL-PE-028 — Update the code of an existing Lambda function and invoke it

| | |
| --- | --- |
| Severity | high (critical when the edge is on a path to Tier 0) |
| Category | existing-passrole |
| Status | stable |
| Edge | `update_code` |
| Required actions | `lambda:UpdateFunctionCode`, `lambda:InvokeFunction` |
| pathfinding.cloud | [lambda-004](https://pathfinding.cloud/paths/aws/lambda-004) |

## Description

The principal can change what an existing resource runs, and that resource already has a role. The new code runs with the role's permissions.

Prerequisites:

- a Lambda function runs with the role

## Why it matters

Escalation paths turn a limited identity into an administrator. Attackers who obtain any credential look for exactly this permission combination; defenders rarely notice it in policy reviews because each statement looks reasonable on its own.

## Attack chain

1. The principal changes what an existing resource runs (`lambda:UpdateFunctionCode`, `lambda:InvokeFunction`).
2. The resource executes that code with its role's credentials.

## Vulnerable example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:UpdateFunctionCode",
        "lambda:InvokeFunction"
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
        "lambda:UpdateFunctionCode",
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:*:111111111111:function:team-a-*"
    }
  ]
}
```

## Remediation

Restrict lambda:UpdateFunctionCode and lambda:InvokeFunction to the resources the caller owns; separate deployment roles from runtime roles.

## References

- https://cwe.mitre.org/data/definitions/266.html
- pathfinding.cloud: [lambda-004](https://pathfinding.cloud/paths/aws/lambda-004)
