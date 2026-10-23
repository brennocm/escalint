# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Repository scaffold: Go module, `escalint version`, embedded web UI with a
  `noui` build tag, Vite + React + strict TypeScript frontend, Makefile, CI.
- Phase 0 research: verified AWS evaluation semantics, edge cases, Tier 0
  definition and the v1 rule catalog (`docs/research.md`).
- Visual language: validated palettes (contrast, CIEDE2000 under color vision
  deficiency), node glyphs, edge styles, detection indicators and static view
  mockups on the `#/design` route (`docs/design.md`).
- ATT&CK v20.0 mapping and CloudTrail detection research (ADR 0021, 0022).
- Policy parser with strict handling of untrusted JSON (ADR 0023) and the
  snapshot loader for authorization details and the escalint envelope.
- Action catalog generated from the AWS service reference (ADR 0012) and
  IAM wildcard matching for actions and ARNs.
- Policy evaluator with SCPs, RCPs, trust policies, boundaries, cross-account
  rules and decision traces (ADR 0004, 0005).
- Can-act-as graph, k shortest escalation paths, cycles, tiers, blast radius,
  choke points and a greedy fix plan (ADR 0006, 0007, 0009, 0010).
- 39 rules: 30 escalation paths (`EL-PE-001`…`030`, 33 pathfinding.cloud
  paths), 6 trust rules (`EL-TR-001`…`006`), 3 diagnostics
  (`EL-PARSE-001`…`003`), each with fixtures and embedded documentation;
  generated `docs/coverage.md` and README rule table.
- Vulnerable and hardened example accounts as integration tests; synthetic
  snapshot generator (`escalint synth`).
- `analysis.json` contract with JSON Schema and a generated TypeScript type;
  text, JSON, SARIF 2.1.0, DOT and Mermaid reporters; `--redact` with
  per-run pseudonyms (ADR 0003, 0010, 0011).
- CLI: `analyze`, `scan`, `diff`, `graph`, `rules list|explain`,
  `attack coverage`, `schema`, `synth`, exit codes, `--deterministic`;
  `.escalint.yaml` with suppressions (mandatory reason, expiry) and groupings.
- Read-only collector (`escalint collect`) with Organizations, resource
  inventory and multi-account role assumption; minimal IAM policy checked by
  a test (ADR 0020).
- Web UI: Overview, Atlas (own WebGL2 renderer, force layout in a worker,
  semantic zoom), Trace, policy explainer, Reach, Exposure, Findings, Fix
  plan, Detect and Diff; URL state, command palette, light and dark themes,
  accessible tables, SVG/PNG export (ADR 0014, 0015, 0016).
- `escalint serve` on loopback with a one-time token, Host check and strict
  CSP; `escalint report --html`, one offline file with a hash-based CSP;
  GitHub Pages demo with synthetic data (ADR 0017, 0018).
- CI: lint, race tests with per-package coverage gates, fuzz smoke,
  govulncheck, generated-file check, Playwright E2E in three browsers,
  visual baselines in the Playwright container, axe, hostile-data tests,
  CodeQL, Scorecard, dependency review; nightly long fuzzing, mutation
  testing and benchmarks; monthly catalog refresh.
- Releases with GoReleaser: binaries with the UI for six platforms, SBOMs,
  keyless-signed checksums, provenance and a signed distroless image on
  ghcr.io; composite GitHub Action with SARIF report, `fail-on` gate and
  baseline diff (ADR 0026).
- README media (`make demo-media`), threat model, benchmarks
  (`make bench-cli`, `docs/benchmarks.md`).

### Performance

- 50,000-principal accounts analyze in about 28 s with a 1.3 GB peak:
  per-account AssumeRole pre-filter, exact-ARN target lookup in pair rules,
  memoized action patterns, and streamed JSON and SARIF output.
- The UI stays responsive with 50,000 principals (Exposure draws only
  visible rows, the Atlas table is memoized, linear grouping).

### Security

- Reject `"Condition": null`, empty element lists and `null` strings in
  policies instead of reading them with a different meaning.
- Decode snapshots with case-sensitive field names (`encoding/json/v2`).
- Escape snapshot-derived text in CLI errors (terminal escape sequences).
- Reject YAML anchors and aliases and unknown keys in `.escalint.yaml`.
- Write every output file with mode 0600.
- Hostile-data tests for `serve` and for the HTML report opened from
  `file://`: no script execution, no CSP violation, no external request.
