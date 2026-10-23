# escalint

**Find every way an AWS IAM principal can become administrator, explain why, and say what to cut.**

[![CI](https://github.com/brennocm/escalint/actions/workflows/ci.yml/badge.svg)](https://github.com/brennocm/escalint/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/brennocm/escalint?sort=semver)](https://github.com/brennocm/escalint/releases)
[![License](https://img.shields.io/github/license/brennocm/escalint)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/brennocm/escalint/badge)](https://scorecard.dev/viewer/?uri=github.com/brennocm/escalint)
[![Go Report Card](https://goreportcard.com/badge/github.com/brennocm/escalint)](https://goreportcard.com/report/github.com/brennocm/escalint)

![The escalint UI: Overview, a critical path in Trace, the policy explainer, the fix plan and the Atlas](docs/media/ui.gif)

**[Live demo](https://brennocm.github.io/escalint/)** (synthetic data, runs entirely in your browser) ·
[MP4 version of the video](docs/media/ui.mp4)

escalint reads an IAM snapshot of one or more AWS accounts, evaluates the
policies the way AWS does (identity policies, permissions boundaries, SCPs,
RCPs, trust policies, explicit denies), builds a graph of who can act as whom,
and reports the privilege escalation paths that end at administrator. It
runs offline, has no database, and ships as one static binary with an
embedded web UI.

## Why

An IAM principal rarely holds `AdministratorAccess` directly. It holds
`iam:PassRole` and `lambda:CreateFunction`, or `iam:CreatePolicyVersion` on a
policy attached to itself, or it may assume a role whose trust policy it can
rewrite. [pathfinding.cloud](https://pathfinding.cloud) catalogs **92**
such AWS privilege escalation paths. Each is easy to miss in review because
no single policy looks dangerous; the danger is in the combination, across
principals and across accounts.

escalint finds those combinations, shows the exact statements that allow each
step, tells you which steps CloudTrail would record, and computes the
smallest set of changes it can find that removes every path.

## Features

- **Faithful evaluation:** explicit deny, SCPs and RCPs by OU level,
  permissions boundaries, trust policies, cross-account rules, `NotAction` /
  `NotResource` / `NotPrincipal`, wildcards in actions and ARNs, and a
  decision trace for every allow. Conditions that cannot be evaluated
  statically make a path `conditional`; nothing is dropped silently.
- **39 rules:** 30 escalation paths (`EL-PE`), 6 trust misconfigurations
  (`EL-TR`, e.g. GitHub Actions OIDC without a `sub` condition), 3 input
  diagnostics (`EL-PARSE`). Every rule cites the AWS docs and its
  pathfinding.cloud ID.
- **Graph analyses:** k shortest paths to Tier 0, privilege tiers, blast
  radius per principal, assume-role cycles, choke points and a greedy fix plan.
- **Detection context:** MITRE ATT&CK techniques per rule and the CloudTrail
  events (or blind spots) of every step.
- **Outputs for CI:** text, JSON, SARIF 2.1.0 (GitHub Code Scanning), DOT,
  Mermaid, exit codes, `diff` against a baseline, suppressions with
  mandatory reasons and expiry.
- **Web UI** with nine views (Overview, Atlas, Trace, Reach, Exposure,
  Findings, Fix plan, Detect, Diff) and a policy explainer, served locally by
  `escalint serve` or as a single offline HTML file (`escalint report
  --html`). Light and dark themes, color-vision-deficiency-safe palettes,
  keyboard navigation and a table behind every graph.
- **Safe with hostile data and shared reports:** strict CSP, no
  `innerHTML`, loopback-only server with a one-time token, and `--redact` to
  replace every identifier with a pseudonym.
- **Read-only collector** with a published minimal IAM policy.

## Install

Release binaries for Linux, macOS and Windows (amd64 and arm64), with the UI
embedded:

```sh
# pick your platform at https://github.com/brennocm/escalint/releases
curl -sSLO https://github.com/brennocm/escalint/releases/download/v0.1.0/escalint_0.1.0_linux_amd64.tar.gz
tar xzf escalint_0.1.0_linux_amd64.tar.gz escalint
./escalint version
```

Container image (distroless, nonroot):

```sh
docker run --rm -v "$PWD:/work" ghcr.io/brennocm/escalint:v0.1.0 scan /work/snapshot.json
```

From source with Go (no web UI: `serve` and `report` need a release binary
or `make web-build build`):

```sh
go install -tags noui github.com/brennocm/escalint/cmd/escalint@latest
```

## Quick start

```sh
escalint collect -o snapshot.json   # read-only calls with your AWS credentials
escalint serve snapshot.json        # opens the UI on 127.0.0.1 with a one-time token
escalint scan snapshot.json         # findings in the terminal; exit 1 on high or critical
```

No credentials at hand? Try the bundled example accounts:

```sh
escalint scan examples/vulnerable-account/snapshot.json   # every stable rule fires
escalint scan examples/hardened-account/snapshot.json \
  --config-file examples/hardened-account/.escalint.yaml  # no findings
```

![The CLI: rules list, scan, diff against a baseline, and a clean account](docs/media/cli.gif)

## Views

| View | Light | Dark |
| --- | --- | --- |
| **Overview**: tiers, critical paths, CloudTrail blind spots, what to fix first | ![Overview, light theme](docs/media/views/overview-light.png) | ![Overview, dark theme](docs/media/views/overview-dark.png) |
| **Atlas**: every principal (WebGL), account areas, semantic zoom, shortest path with Shift+click | ![Atlas, light theme](docs/media/views/atlas-light.png) | ![Atlas, dark theme](docs/media/views/atlas-dark.png) |
| **Trace**: one path step by step, alternatives and choke points; click an edge for the policy explainer | ![Trace, light theme](docs/media/views/trace-light.png) | ![Trace, dark theme](docs/media/views/trace-dark.png) |
| **Reach**: what a principal can reach, and who can reach it, in rings by hop | ![Reach, light theme](docs/media/views/reach-light.png) | ![Reach, dark theme](docs/media/views/reach-dark.png) |
| **Exposure**: principals × services by capability class, similar profiles grouped | ![Exposure, light theme](docs/media/views/exposure-light.png) | ![Exposure, dark theme](docs/media/views/exposure-dark.png) |
| **Findings**: filterable table, CSV export | ![Findings, light theme](docs/media/views/findings-light.png) | ![Findings, dark theme](docs/media/views/findings-dark.png) |
| **Fix plan**: ordered changes with a live preview of the paths that remain | ![Fix plan, light theme](docs/media/views/fix-light.png) | ![Fix plan, dark theme](docs/media/views/fix-dark.png) |
| **Detect**: CloudTrail events per step, blind spots, exhibited ATT&CK techniques | ![Detect, light theme](docs/media/views/detect-light.png) | ![Detect, dark theme](docs/media/views/detect-dark.png) |
| **Diff**: what changed between two snapshots, anchored by stable IDs | ![Diff, light theme](docs/media/views/diff-light.png) | ![Diff, dark theme](docs/media/views/diff-dark.png) |

## Usage

| Command | What it does |
| --- | --- |
| `escalint collect` | Read-only snapshot of IAM (and optionally Organizations, Lambda, EC2, CodeBuild) ([docs/collector.md](docs/collector.md)) |
| `escalint scan <snapshot>` | Findings as `text`, `json` ([format](docs/output-json.md)) or `sarif` |
| `escalint diff <before> <after>` | Added and removed edges, paths and findings; gates only on added ones |
| `escalint analyze <snapshot>` | The full `analysis.json` (graph, paths, findings, fix plan), the UI contract ([schema](schema/analysis.v1.schema.json)) |
| `escalint serve <snapshot>` | The web UI on `127.0.0.1`, random port, one-time token |
| `escalint report --html <snapshot>` | One self-contained HTML file that works offline |
| `escalint graph <snapshot>` | The graph or one path as Graphviz DOT or Mermaid |
| `escalint rules list` / `rules explain <ID>` | The rule catalog and each rule's documentation |
| `escalint attack coverage` | Rules by MITRE ATT&CK technique |
| `escalint schema` | The JSON Schema of `analysis.json` |
| `escalint synth` | Synthetic snapshots for benchmarks and demos |

Inputs are an escalint snapshot or the output of
`aws iam get-account-authorization-details`; most commands also accept an
`analysis.json`.

Common flags: `--format`, `--output` (files are written with mode 0600),
`--fail-on <severity|none>` (default `high`), `--min-severity`,
`--experimental` / `--enable` / `--disable` for rule selection,
`--max-depth` (default 6) and `--k-paths` (default 3), `--redact`,
`--deterministic` (byte-for-byte reproducible output), `--config-file`.

**Exit codes:** `0` no unsuppressed finding at or above `--fail-on`, `1`
such findings exist, `2` usage or runtime error.

**Configuration:** `.escalint.yaml` in the working directory sets trusted
and third-party accounts, suppressions (rule, ARN glob, mandatory reason,
optional expiry), groupings for the UI and defaults for rule selection and
the gate. Suppressed findings are never removed from the output; they are
marked. See [docs/configuration.md](docs/configuration.md).

## GitHub Action

The action builds escalint from its own source at the ref you pin, writes a
report (SARIF by default) and then gates on `fail-on`, against a `baseline`
snapshot when you give one. Inputs: `snapshot`, `baseline`, `format`,
`output`, `fail-on`, `min-severity`, `experimental`, `redact`, `config-file`.

A daily job that collects with a read-only role through OIDC, compares with
yesterday's snapshot and uploads the findings to Code Scanning:

```yaml
name: iam-escalation
on:
  schedule: [{ cron: "17 6 * * *" }]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  escalint:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      id-token: write          # OIDC to AWS
      security-events: write   # upload SARIF
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd # v6.3.0
        with:
          role-to-assume: arn:aws:iam::111111111111:role/escalint-readonly  # docs/collector-policy.json
          aws-region: us-east-1
      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: baseline.json
          key: escalint-baseline-${{ github.run_id }}
          restore-keys: escalint-baseline-
      - name: Collect
        run: |
          go run -tags noui github.com/brennocm/escalint/cmd/escalint@v0.1.0 collect -o snapshot.json
          test -f baseline.json || cp snapshot.json baseline.json
      - uses: brennocm/escalint@<commit-sha> # v0.1.0
        with:
          snapshot: snapshot.json
          baseline: baseline.json
          fail-on: high
      - uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        if: always()
        with:
          sarif_file: escalint.sarif
      - run: mv snapshot.json baseline.json
      - uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: baseline.json
          key: escalint-baseline-${{ github.run_id }}
```

The snapshot stays in the runner and in the repository's Actions cache;
use `redact: "true"` if the job log or the SARIF is visible to people who
should not see your account's identifiers.

## Rules

<!-- rules:begin (generated by make gen-docs) -->
| Rule | Title | Severity | Status | pathfinding.cloud |
| --- | --- | --- | --- | --- |
| [EL-PARSE-001](docs/rules/EL-PARSE-001.md) | Policy document could not be parsed | info | stable | — |
| [EL-PARSE-002](docs/rules/EL-PARSE-002.md) | Referenced policy or group is not in the snapshot | info | stable | — |
| [EL-PARSE-003](docs/rules/EL-PARSE-003.md) | Suppression without a justification | info | stable | — |
| [EL-PE-001](docs/rules/EL-PE-001.md) | Create a new default version of an attached policy | critical | stable | iam-001 |
| [EL-PE-002](docs/rules/EL-PE-002.md) | Put an inline policy on its own role | critical | stable | iam-005 |
| [EL-PE-003](docs/rules/EL-PE-003.md) | Put an inline policy on its own user | critical | stable | iam-007 |
| [EL-PE-004](docs/rules/EL-PE-004.md) | Attach a managed policy to its own user | critical | stable | iam-008 |
| [EL-PE-005](docs/rules/EL-PE-005.md) | Attach a managed policy to its own role | critical | stable | iam-009 |
| [EL-PE-006](docs/rules/EL-PE-006.md) | Attach a managed policy to its own group | critical | stable | iam-010 |
| [EL-PE-007](docs/rules/EL-PE-007.md) | Put an inline policy on its own group | critical | stable | iam-011 |
| [EL-PE-008](docs/rules/EL-PE-008.md) | Add itself to a more privileged group | high | stable | iam-013 |
| [EL-PE-009](docs/rules/EL-PE-009.md) | Create an access key for another user | high | stable | iam-002 |
| [EL-PE-010](docs/rules/EL-PE-010.md) | Rotate out and create an access key for another user | high | stable | iam-003 |
| [EL-PE-011](docs/rules/EL-PE-011.md) | Create a console password for another user | high | stable | iam-004 |
| [EL-PE-012](docs/rules/EL-PE-012.md) | Change another user's console password | high | stable | iam-006 |
| [EL-PE-013](docs/rules/EL-PE-013.md) | Rewrite a role's trust policy | high | stable | iam-012 |
| [EL-PE-014](docs/rules/EL-PE-014.md) | Assume a more privileged role | medium | stable | sts-001 |
| [EL-PE-015](docs/rules/EL-PE-015.md) | Attach a policy to a role it can assume | critical | stable | iam-014 |
| [EL-PE-016](docs/rules/EL-PE-016.md) | Create a new policy version for a role it can assume | critical | stable | iam-016 |
| [EL-PE-017](docs/rules/EL-PE-017.md) | Put an inline policy on a role it can assume | critical | stable | iam-017 |
| [EL-PE-018](docs/rules/EL-PE-018.md) | Attach a policy to a user and create its access key | critical | stable | iam-015 |
| [EL-PE-019](docs/rules/EL-PE-019.md) | Put an inline policy on a user and create its access key | critical | stable | iam-018 |
| [EL-PE-020](docs/rules/EL-PE-020.md) | Modify a role's permissions and rewrite its trust | critical | stable | iam-019, iam-020, iam-021 |
| [EL-PE-021](docs/rules/EL-PE-021.md) | Pass a role to a new EC2 instance | high | stable | ec2-001 |
| [EL-PE-022](docs/rules/EL-PE-022.md) | Pass a role to a new Lambda function and invoke it | high | stable | lambda-001 |
| [EL-PE-023](docs/rules/EL-PE-023.md) | Pass a role to a new CloudFormation stack | high | stable | cloudformation-001 |
| [EL-PE-024](docs/rules/EL-PE-024.md) | Pass a role to a new CodeBuild project | high | stable | codebuild-001 |
| [EL-PE-025](docs/rules/EL-PE-025.md) | Pass a role to a new Glue job | high | stable | glue-003 |
| [EL-PE-026](docs/rules/EL-PE-026.md) | Pass a role to a new ECS task | high | experimental | ecs-002, ecs-004 |
| [EL-PE-027](docs/rules/EL-PE-027.md) | Pass a role to a new SageMaker notebook | high | stable | sagemaker-001 |
| [EL-PE-028](docs/rules/EL-PE-028.md) | Update the code of an existing Lambda function and invoke it | high | stable | lambda-004 |
| [EL-PE-029](docs/rules/EL-PE-029.md) | Run a command on an instance that has a role | high | experimental | ssm-002 |
| [EL-PE-030](docs/rules/EL-PE-030.md) | Start a build of an existing CodeBuild project | high | experimental | codebuild-002 |
| [EL-TR-001](docs/rules/EL-TR-001.md) | Role trusts any AWS principal | critical | stable | — |
| [EL-TR-002](docs/rules/EL-TR-002.md) | GitHub Actions OIDC trust without a sub condition | critical | stable | — |
| [EL-TR-003](docs/rules/EL-TR-003.md) | GitHub Actions OIDC trust with a broad sub pattern | high | stable | — |
| [EL-TR-004](docs/rules/EL-TR-004.md) | Trust to an external account outside the allowlist | medium | stable | — |
| [EL-TR-005](docs/rules/EL-TR-005.md) | Third-party trust without sts:ExternalId | high | stable | — |
| [EL-TR-006](docs/rules/EL-TR-006.md) | OIDC or SAML trust without an audience or subject condition | medium | experimental | — |

39 rules; 33 of the 92 AWS paths on pathfinding.cloud are covered ([docs/coverage.md](docs/coverage.md)).
<!-- rules:end -->

`escalint rules explain EL-PE-022` prints a rule's documentation; the same
pages are in [docs/rules](docs/rules). Experimental rules are off by default
(`--experimental`).

### MITRE ATT&CK

`escalint attack coverage` lists the rules per technique (Enterprise ATT&CK
v20.0, [ADR 0021](docs/adr/0021-mitre-attack-mapping.md)); with a snapshot
it lists the techniques that account exhibits. Every finding in text, JSON,
SARIF and the UI carries its techniques.

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE
Corporation. © 2026 The MITRE Corporation. This work is reproduced and
distributed with the permission of The MITRE Corporation.

## Performance

<!-- bench:begin -->
On a 4-core laptop, synthetic accounts ([docs/benchmarks.md](docs/benchmarks.md), `make bench-cli`):

| Principals | `escalint analyze` | Peak memory |
| ---: | ---: | ---: |
| 1,000 | 0.2 s | 47 MB |
| 10,000 | 2.2 s | 188 MB |
| 50,000 | 28 s | 1.3 GB |

The UI loads in 78.8 KB of gzipped JavaScript, shows the Overview of a
10,000-principal account within 1.2 s of the data arriving, pans the Atlas at
a median 16.7 ms per frame, and stays responsive with 50,000 principals
through semantic zoom.
<!-- bench:end -->

## Design

The engine is a pipeline of small Go packages with no dependencies beyond
the standard library: strict parsing of untrusted JSON, an IAM evaluator that
returns a trace for each decision, a can-act-as graph, rules that add
escalation edges, and graph analyses. Its output, `analysis.json`, is the
only contract with the UI, a React + strict TypeScript app with its own WebGL
renderer, layouts, store and router, embedded in the binary. Everything is
deterministic: same snapshot, same bytes. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), the visual language in
[docs/design.md](docs/design.md) and the decision records in
[docs/adr](docs/adr).

## Security

- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Reporting a
  vulnerability: [SECURITY.md](SECURITY.md).
- Snapshots, `analysis.json` and reports are a map of who can become
  administrator. Keep them private; share only with `--redact`.
- Releases are built in GitHub Actions from a tag. Verify the checksums
  file with [cosign](https://docs.sigstore.dev/) and the provenance with the
  GitHub CLI, then check your archive against the checksums:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/brennocm/escalint/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify escalint_0.1.0_linux_amd64.tar.gz --repo brennocm/escalint
sha256sum --ignore-missing -c checksums.txt

cosign verify ghcr.io/brennocm/escalint:v0.1.0 \
  --certificate-identity-regexp '^https://github.com/brennocm/escalint/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Limitations

- **Not modeled in v1:** session policies and session tags, resource-based
  policies other than role trust (S3 bucket policies, KMS key policies and
  grants, Lambda function policies, Secrets Manager), root users,
  IAM Identity Center assignments, role chaining limits. See
  [docs/research.md §5](docs/research.md) and
  [ADR 0004](docs/adr/0004-evaluation-model.md).
- **Request-time conditions** (MFA, source IP, time, tags on the request)
  cannot be known statically: affected steps are `conditional`, never
  dropped.
- **Coverage:** 33 of the 92 pathfinding.cloud paths; most of the rest pass a
  role to another compute service and follow the same template
  ([docs/coverage.md](docs/coverage.md)).
- **A snapshot is a point in time.** Re-collect after changes.
- **The resource inventory is regional:** resources in regions not passed to
  `collect --regions` are not seen ([docs/collector.md](docs/collector.md)).
- The fix plan is greedy: small, not guaranteed minimal
  ([ADR 0009](docs/adr/0009-fix-plan.md)).

## Acknowledgements

- [pathfinding.cloud](https://pathfinding.cloud) (Datadog) for the catalog of
  AWS privilege escalation paths that the rules reference.
- [aws-iam-graph](https://github.com/marcelogsantos/aws-iam-graph) by
  marcelogsantos, which inspired escalint: a self-hosted graph of roles where
  no data leaves the account. escalint is a reimplementation from scratch;
  no code was copied.
- [PMapper](https://github.com/nccgroup/PMapper) (NCC Group) for showing
  that IAM is best understood as a graph.
- The [AWS service reference information](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)
  for the machine-readable action catalog.
- [MITRE ATT&CK](https://attack.mitre.org) for the technique mapping.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for licenses.

## Disclaimer

escalint is an independent project. It is not affiliated with, endorsed by
or sponsored by Amazon Web Services, Datadog or MITRE. It reads your account
and never changes it, but its results are an aid to review, not a guarantee
that an account is safe.

## License

[Apache License 2.0](LICENSE).
