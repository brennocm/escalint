# EL-TR-003 — GitHub Actions OIDC trust with a broad sub pattern

| | |
| --- | --- |
| Severity | high |
| Category | trust |
| Status | stable |
| Subject | the role whose trust policy is too broad |
| Required actions | `sts:AssumeRoleWithWebIdentity` |

## Description

The role trusts GitHub Actions and restricts `sub`, but the pattern admits many repositories or every ref of a repository: `*`, `repo:*`, `repo:<org>/*`, or `repo:<org>/<repo>` followed by nothing or `:*`.

The finding is reported only when escalint's evaluator lets the principal assume the role: explicit denies, resource control policies and the condition keys escalint evaluates are applied first.

## Why it matters

A wildcard in the organization lets other GitHub organizations in; a wildcard in the repository lets any repository of the organization (including forks and new, less protected repositories) in; a wildcard ref lets any branch, including unreviewed pull request branches, deploy with the role.

## Attack chain

1. The attacker gains write access to any repository or branch the pattern covers (or creates one when the organization part is a wildcard).
2. A workflow there requests an OIDC token and calls `sts:AssumeRoleWithWebIdentity`.
3. The `sub` claim matches the broad pattern and the workflow acts as the role.

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
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:example-org/*"
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
          "token.actions.githubusercontent.com:sub": "repo:example-org/deploy:environment:production"
        }
      }
    }
  ]
}
```

## Remediation

Pin `sub` to one repository and a protected branch, tag or GitHub environment (environments can require reviewers). Avoid wildcards in the organization and repository parts.

## References

- https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- https://cwe.mitre.org/data/definitions/284.html
