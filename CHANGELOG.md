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

### Security

- Reject `"Condition": null`, empty element lists and `null` strings in
  policies instead of reading them with a different meaning.
- Decode snapshots with case-sensitive field names (`encoding/json/v2`).
- Escape snapshot-derived text in CLI errors (terminal escape sequences).
