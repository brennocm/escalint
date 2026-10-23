# EL-PARSE-002 — Referenced policy or group is not in the snapshot

| | |
| --- | --- |
| Severity | info |
| Category | parse |
| Status | stable |

## Description

A user, group or role references a managed policy, a permissions boundary
or a group that the snapshot does not contain. This happens when
authorization details were collected with a filter (for example without
`AWSManagedPolicy`).

## Why it matters

The permissions of the missing policy are unknown, so every decision that
depends on it is `conditional`: it might allow, or deny, what the rest of
the policies say.

## Attack chain

Not an attack by itself; it reduces what the analysis can prove.

## Vulnerable example

```json
{"UserDetailList": [{"UserName": "alice", "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}], "Policies": []}
```

## Fixed example

```json
{"UserDetailList": [{"UserName": "alice", "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}],
 "Policies": [{"Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "DefaultVersionId": "v1", "PolicyVersionList": ["…"]}]}
```

## References

- https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html
