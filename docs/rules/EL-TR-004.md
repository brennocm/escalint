# EL-TR-004 — Trust to an external account outside the allowlist

| | |
| --- | --- |
| Severity | medium |
| Category | trust |
| Status | stable |
| Subject | the role whose trust policy is too broad |
| Required actions | `sts:AssumeRole` |

## Description

The trust policy names an AWS account (or a principal in it) that is not part of the snapshot and is not listed in `trusted_accounts` or `third_party_accounts` of `.escalint.yaml`.

The finding is reported only when escalint's evaluator lets the principal assume the role: explicit denies, resource control policies and the condition keys escalint evaluates are applied first.

## Why it matters

Every identity in that account that is allowed to call `sts:AssumeRole` can act as the role. Unknown accounts in trust policies are often leftovers from old vendors, mergers or tests, and nobody reviews who controls them today.

## Attack chain

1. An identity in the external account calls `sts:AssumeRole` on the role.
2. The trust policy admits the account; the identity obtains the role's credentials.

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
        "AWS": "arn:aws:iam::222222222222:role/deployer"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Remediation

Confirm who owns the account. List it in `trusted_accounts` (your organization) or `third_party_accounts` (vendors, then EL-TR-005 checks `sts:ExternalId`), or remove it from the trust policy. Prefer naming a specific role over the account root.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html
- https://cwe.mitre.org/data/definitions/284.html
