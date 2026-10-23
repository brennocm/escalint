# 0025 — Go dependency budget

Status: Accepted

## Context

Every dependency is code that runs on machines holding IAM data and in a
release pipeline that signs binaries. The analysis must work offline.

## Decision

Direct dependencies, each with its reason:

| Module | License | Used by | Why |
| --- | --- | --- | --- |
| `github.com/spf13/cobra` | Apache-2.0 | CLI | conventional flags, help and completion; the standard choice |
| `go.yaml.in/yaml/v3` | Apache-2.0 / MIT | `.escalint.yaml` | YAML is what users expect for config; decoded strictly, anchors and aliases rejected |
| `github.com/aws/aws-sdk-go-v2/...` (config, credentials, sts, iam, organizations, lambda, ec2, ssm, codebuild) | Apache-2.0 | `collect` only (ADR 0020) | credential chain, signing, pagination and retries done right |

Test-only (never linked into the binary):

| Module | License | Why |
| --- | --- | --- |
| `pgregory.net/rapid` | MPL-2.0 | property tests (ADR 0024) |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 | validate analysis.json and SARIF against their schemas |
| `github.com/rogpeppe/go-internal` (testscript) | BSD-3-Clause | CLI end-to-end scripts |

Everything else is the standard library (including `encoding/json/v2` for
untrusted input, ADR 0023). No graph database, no ORM, no web framework.

New dependencies require an update of this table, a license on the
dependency-review allowlist and a release at least seven days old
(Dependabot cooldown).

## Consequences

- The analysis packages (`snapshot` … `report`) depend only on the
  standard library; `govulncheck` runs in CI and nightly.
