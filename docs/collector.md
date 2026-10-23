# Collecting a snapshot

```sh
escalint collect -o snapshot.json                 # current credentials
escalint collect --profile audit --org -o snapshot.json
escalint collect --resources lambda,ec2,codebuild --regions us-east-1,eu-west-1
escalint collect --assume-roles roles.txt         # more accounts, one role ARN per line
```

The collector uses the default AWS credential chain and makes only
read-only calls. The minimal IAM policy is
[`collector-policy.json`](collector-policy.json): the `EscalintCore`
statement is enough for `escalint collect`; the optional statements enable
`--org`, `--resources` and `--assume-roles`. A test keeps the policy in sync
with the code.

Alternatively, without escalint on the machine that has credentials:

```sh
aws iam get-account-authorization-details > snapshot.json
```

That file lacks identity providers, access key counts and login profiles,
so a few rules report `conditional` edges instead.

## Handling the snapshot

A snapshot is a map of who can become administrator. It is written with
mode 0600; keep it out of version control (the repository `.gitignore`
already ignores `snapshot.json`) and use `--redact` before sharing any
report.

## Optional: ground truth with pathfinding-labs

[pathfinding-labs](https://github.com/DataDog/pathfinding-labs) deploys
deliberately vulnerable IAM scenarios with Terraform. To confirm each rule
fires:

1. Use a **disposable** AWS account with no production data.
2. `terraform apply` the scenarios you want (IAM resources are free; some
   scenarios create Lambda, EC2 or CodeBuild resources with small costs).
3. `escalint collect --resources lambda,ec2,codebuild -o labs.json` and
   `escalint scan labs.json`.
4. `terraform destroy` immediately afterwards and check that no resources
   remain.

The escalint maintainers did not run this against any real account while
building v1; the rule fixtures under `internal/rules/testdata` encode the
same scenarios.
