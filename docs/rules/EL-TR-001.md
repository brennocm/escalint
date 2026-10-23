# EL-TR-001 — Role trusts any AWS principal

| | |
| --- | --- |
| Severity | critical |
| Category | trust |
| Status | stable |
| Subject | the role whose trust policy is too broad |
| Required actions | `sts:AssumeRole` |

## Description

The trust policy names `"*"` (or `{"AWS": "*"}`) as principal with no condition that restricts it to your organization, account or specific roles. Any AWS identity in any account can call `sts:AssumeRole` on the role.

The finding is reported only when escalint's evaluator lets the principal assume the role: explicit denies, resource control policies and the condition keys escalint evaluates are applied first.

## Why it matters

The role is effectively public: anyone with an AWS account who learns its ARN (ARNs leak in logs, CloudFormation templates, error messages) obtains its permissions. When the role is privileged, this is an unauthenticated path to administrator.

## Attack chain

1. An attacker creates or uses any AWS account.
2. The attacker calls `sts:AssumeRole` with the role ARN and receives temporary credentials.
3. The attacker acts with the role's permissions.

## Vulnerable example

Trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole"
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
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-exampleorg1"
        }
      }
    }
  ]
}
```

## Remediation

Name the accounts or roles that may assume the role in `Principal`, or add a condition on `aws:PrincipalOrgID`, `aws:PrincipalAccount` or `aws:PrincipalArn`. escalint evaluates these three keys, so a restricted trust produces no finding.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
- https://cwe.mitre.org/data/definitions/284.html
