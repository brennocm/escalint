# EL-TR-002 — GitHub Actions OIDC trust without a sub condition

| | |
| --- | --- |
| Severity | critical |
| Category | trust |
| Status | stable |
| Subject | the role whose trust policy is too broad |
| Required actions | `sts:AssumeRoleWithWebIdentity` |

## Description

The role trusts the GitHub Actions OIDC provider (`token.actions.githubusercontent.com`) and no statement restricts the `token.actions.githubusercontent.com:sub` claim. The `aud` condition alone only proves the token was issued for AWS STS, not which repository asked for it.

The finding is reported only when escalint's evaluator lets the principal assume the role: explicit denies, resource control policies and the condition keys escalint evaluates are applied first.

## Why it matters

Every GitHub repository, including ones the attacker creates for free, can obtain an OIDC token from the same issuer. Without a `sub` condition any of their workflows can call `sts:AssumeRoleWithWebIdentity` and receive the role's credentials.

## Attack chain

1. The attacker creates a public repository with a workflow that requests an OIDC token (`permissions: id-token: write`).
2. The workflow calls `sts:AssumeRoleWithWebIdentity` with the victim's role ARN.
3. STS accepts the token because only `aud` is checked; the workflow now acts as the role.

## Vulnerable example

Trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        }
      }
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
        "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:example-org/deploy:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

## Remediation

Add a `token.actions.githubusercontent.com:sub` condition pinned to one repository and a branch, tag or environment, together with the `aud` condition.

## References

- https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
- https://cwe.mitre.org/data/definitions/284.html
