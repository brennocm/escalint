# EL-TR-005 — Third-party trust without sts:ExternalId

| | |
| --- | --- |
| Severity | high |
| Category | trust |
| Status | stable |
| Subject | the role whose trust policy is too broad |
| Required actions | `sts:AssumeRole` |

## Description

An account listed in `third_party_accounts` of `.escalint.yaml` can assume the role and the trusting statement has no `sts:ExternalId` condition.

The finding is reported only when escalint's evaluator lets the principal assume the role: explicit denies, resource control policies and the condition keys escalint evaluates are applied first.

## Why it matters

Vendors assume roles in many customers' accounts. Without an external ID, any other customer of the same vendor can ask the vendor to access *your* role ARN, and the vendor's identity will succeed: the confused deputy problem.

## Attack chain

1. The attacker becomes a customer of the same vendor and registers the victim's role ARN as "their" role.
2. The vendor's service calls `sts:AssumeRole` on the victim's role on the attacker's behalf.
3. Without an `sts:ExternalId` condition the call succeeds and the attacker reads the results through the vendor.

## Vulnerable example

Trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::999999999999:root"
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
        "AWS": "arn:aws:iam::999999999999:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "vendor-assigned-id"
        }
      }
    }
  ]
}
```

## Remediation

Add `"Condition": {"StringEquals": {"sts:ExternalId": "<value the vendor gave you>"}}` to the statement that trusts the vendor account.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- https://cwe.mitre.org/data/definitions/441.html
