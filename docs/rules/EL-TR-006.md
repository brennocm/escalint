# EL-TR-006 — OIDC or SAML trust without an audience or subject condition

| | |
| --- | --- |
| Severity | medium |
| Category | trust |
| Status | experimental |
| Subject | the role whose trust policy is too broad |
| Required actions | `sts:AssumeRoleWithWebIdentity`, `sts:AssumeRoleWithSAML` |

## Description

The role trusts an OIDC provider other than GitHub Actions and has no condition on `<provider>:aud` or `<provider>:sub`, or trusts a SAML provider without a `SAML:aud` condition. Also covers `sts:AssumeRoleWithSAML`.

The finding is reported only when escalint's evaluator lets the principal assume the role: explicit denies, resource control policies and the condition keys escalint evaluates are applied first.

## Why it matters

OIDC providers issue tokens for many applications and users; without an audience or subject condition, a token issued for another application of the same provider may be accepted. SAML without `SAML:aud` accepts assertions meant for other service providers. This rule is experimental because some providers enforce audiences themselves.

## Attack chain

1. The attacker obtains a token or assertion from the provider for a different application or identity.
2. The attacker calls `sts:AssumeRoleWithWebIdentity` (or `sts:AssumeRoleWithSAML`) with it.
3. With no audience or subject condition, STS accepts it and the attacker acts as the role.

## Vulnerable example

Trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
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
        "Federated": "arn:aws:iam::111111111111:oidc-provider/oidc.example.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.example.com:aud": "example-app"
        }
      }
    }
  ]
}
```

## Remediation

Add a condition on the provider's `aud` (and `sub` for OIDC) keys, or `SAML:aud` for SAML, so only the intended application and identities can assume the role.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html
- https://cwe.mitre.org/data/definitions/284.html
