# Threat model

A STRIDE summary for escalint v0.1. It covers the CLI, the analysis engine,
the collector, `escalint serve`, the single-file HTML report, the GitHub
Pages demo, the GitHub Action and the release pipeline.

## Assets

| Asset | Why it matters |
| --- | --- |
| Snapshot and `analysis.json` | A map of who can become administrator in the account: an attacker's to-do list. |
| Collector credentials | Read access to IAM (and optionally Organizations, Lambda, EC2, CodeBuild, SSM). |
| Integrity of the results | A missed path is a false sense of safety; a CI gate that passes wrongly lets a regression in. |
| The machine or CI runner | escalint parses untrusted input there. |
| The browser of whoever opens the UI or report | It renders names and policies chosen by people with access to the account. |

## Adversaries

1. Someone who controls names, tags, paths or policy documents in an analyzed
   account (they want XSS or injection through the data).
2. Someone who sends a tampered HTML report.
3. Another local process, or a web page in the user's browser, trying to read
   a running `serve` (CSRF, DNS rebinding).
4. A compromised dependency or GitHub Action.
5. Someone who tampers with a release or an image.
6. A pull request author who tries to hide a finding (suppression,
   configuration change) or to exploit the CI workflows.

## Threats and mitigations

| STRIDE | Threat | Mitigation | Evidence |
| --- | --- | --- | --- |
| Tampering / Elevation | XSS through principal names, tags or policies in the UI | No `innerHTML`, `dangerouslySetInnerHTML`, `eval` or `new Function` (ESLint rule); text in SVG through text nodes, in Canvas/WebGL through `fillText`; strict CSP without `'unsafe-inline'`/`'unsafe-eval'` | `web/tests/security/` (hostile fixture: script payloads, `javascript:` URLs, RTL override, 64 KB strings) through `serve` and `file://`: no script runs, zero CSP violations, zero external requests |
| Tampering | Terminal escape sequences or Mermaid directives in names reaching the CLI output | `internal/termsafe` escapes control characters in text output and errors; an `analysis.json` read back must have IDs, kinds and statuses matching the schema patterns | `internal/termsafe` tests and fuzz target; `internal/contract/validate_test.go` |
| Spoofing / Information disclosure | Another process or web page reads `serve` | Loopback bind on a random port; non-loopback needs `--listen` and `--allow-remote`; one-time token exchanged for a separate session value in an `HttpOnly; SameSite=Strict` cookie; constant-time comparison; `Host` allowlist (421) against DNS rebinding; GET only (405); `frame-ancestors 'none'` (ADR 0017) | `internal/server` handler tests; `web/tests/serve` against the real binary |
| Tampering | A tampered HTML report executes extra code | Inline script and style allowed only by SHA-256 hash in the CSP (ADR 0018); `connect-src 'none'`. A report edited by an attacker is a new, untrusted file: escalint cannot protect a reader who opens it, so share reports through trusted channels. | `web/tests/serve/report.spec.ts` (file://, every view, zero CSP violations, zero requests) |
| Information disclosure | The privilege map leaks when a report is shared | `--redact`: account IDs, names, ARNs, tags and IDs replaced by HMAC pseudonyms with a per-run random key, including tag names in condition keys, private identity provider hosts, GitHub organizations and repositories, and file paths; the report says it is redacted; outputs are written with mode 0600 | `internal/redact` and `internal/report` property tests: no original identifier appears in any redacted output |
| Denial of service | Hostile JSON or YAML hangs or exhausts the analyzer | Size limits (200 MiB input, 128 KiB per policy, 1 MiB config), depth limits, statement and value caps, duplicate-key and BOM handling (ADR 0023); YAML anchors and aliases rejected; no regexps on input (wildcards matched by a linear matcher) | Fuzz targets for every parser and matcher (`make fuzz`, nightly 10 min each); `internal/contract/robustness_test.go`; 50,000 principals measured in `docs/benchmarks.md` |
| Repudiation / Tampering | A false negative is silent | Unevaluated conditions and unmodeled prerequisites make an edge `conditional`, never dropped (ADR 0005); every stable rule has positive and negative fixtures; `examples/vulnerable-account` must fire every stable rule and `hardened-account` none; pathfinding.cloud coverage is published (`docs/coverage.md`) | `internal/rules` harness, `internal/engine/examples_test.go` |
| Tampering | A pull request suppresses findings quietly | Suppressions need a reason (otherwise `EL-PARSE-003` and no effect), may expire, and are never removed from outputs (JSON, SARIF, UI list them); `diff` gates only on added findings so a baseline cannot be edited away silently | `internal/suppress`, `internal/config` tests |
| Elevation | The collector holds more permissions than it needs | Read-only calls only; the minimal policy is published in `docs/collector-policy.json` and a test checks it against the calls in the code; no network access outside `collect` | `internal/collect/policy_test.go` |
| Tampering (supply chain) | A compromised dependency | Few dependencies (ADR 0013, 0025); lockfiles; Dependabot with a cooldown; dependency review (licenses, high vulnerabilities); `govulncheck`; CodeQL; OpenSSF Scorecard | CI and nightly workflows |
| Tampering (CI) | A workflow is abused by a pull request | `permissions: contents: read` by default, extra permissions per job; every action pinned by commit SHA; `persist-credentials: false`; no `pull_request_target`; inputs reach shells through environment variables; actionlint and zizmor in CI | `workflow-lint` job |
| Spoofing (release) | A tampered binary or image | GoReleaser in CI from a tag; checksums signed keyless with cosign; SBOMs; build provenance attestation; image on distroless nonroot pinned by digest and signed (ADR 0026) | Verification commands in the README |

## Accepted residual risks

- **The model is incomplete.** escalint v1 does not model resource-based
  policies beyond role trust (S3, KMS, Lambda, Secrets Manager), session
  policies, permission sets created after collection, or service-specific
  behavior beyond the documented rules. It reports what it cannot evaluate as
  `conditional`, but paths through unmodeled mechanisms are not found.
- **A snapshot is a point in time.** Changes after collection are invisible.
- **The resource inventory is regional and taken as complete.** Resources
  in regions that were not collected produce no `update_code` edges.
- **`serve --allow-remote` is plain HTTP.** The Host check accepts the
  listen address (every local interface address for a wildcard bind such as
  `0.0.0.0`, the given name for `--listen my-host:port`), but the token and
  the analysis cross the network unencrypted. Remote use is discouraged (use
  the HTML report).
- **Shared reports are trusted by their readers.** escalint cannot stop a
  modified HTML file from doing harm once someone opens it; the CSP limits
  what the original file can do, not what an attacker writes into a new one.
- **The pseudonyms of `--redact` hide identifiers, not structure.** The shape
  of the graph (how many roles, which services, which paths) remains visible.
- **`serve` on loopback is visible to the local user's own processes.** The
  token stops other processes that did not see the printed URL; it does not
  stop malware running as the same user.
- **The GitHub Action builds from source at the ref the caller pins.** A
  caller who uses a branch instead of a commit SHA trusts every future commit
  on that branch.
