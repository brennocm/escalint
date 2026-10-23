# Security policy

## Supported versions

escalint is pre-1.0. Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's
[private vulnerability reporting](https://github.com/brennocm/escalint/security/advisories/new)
for this repository. Include:

- the affected version (`escalint version`);
- a minimal snapshot or `analysis.json` that reproduces the issue, with all
  identifiers replaced by fake values (`111111111111`, `example-role`);
- the impact you observed.

You can expect an acknowledgement within 7 days. Fixes are released as soon as
practical and credited in the changelog unless you prefer otherwise.

## Scope

In scope: the CLI, the analysis engine, the `serve` web server, the
self-contained HTML report, the GitHub Action and the release artifacts.
Examples: XSS through data in a snapshot, access to `serve` from another
origin, a crafted snapshot that crashes or hangs the analyzer, a missed or
silently dropped escalation path, leakage of identifiers when `--redact` is set.

Out of scope: findings in AWS itself, and misconfigurations that escalint
correctly reports.

## Handling account data

Snapshots and `analysis.json` files are a map of who can reach what in your
account. Treat them as sensitive, share them only with `--redact`, and never
attach unredacted files to issues.
