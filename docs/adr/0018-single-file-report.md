# 0018 — Single-file HTML report and hash-based CSP

Status: Accepted

## Context

A report must open offline from `file://`, be easy to attach to a ticket,
and keep the UI's protections against hostile names and policies: no
`'unsafe-inline'`, no network.

## Decision

- The web build has a `report` mode (`vite build --mode report`, output in
  `web/dist/report`): one JavaScript bundle (dynamic imports inlined), one
  stylesheet with the fonts inlined as data URIs, and no layout worker
  (the force layout runs on the main thread).
- `escalint report --html` (package `internal/htmlreport`) inlines the
  script and the stylesheet, adds the analysis as
  `<script type="application/json" id="escalint-data">` (JSON with `<`, `>`
  and `&` escaped), and writes a `<meta http-equiv="Content-Security-Policy">`
  whose `script-src` and `style-src` are the SHA-256 hashes of exactly those
  inline blocks: `default-src 'none'; script-src 'sha256-…'; style-src
  'sha256-…'; img-src data: blob:; font-src data:; connect-src 'none';
  worker-src 'none'; base-uri 'none'; form-action 'none'`.
- Hashes are computed when the report is written, from the bytes inlined,
  so they always match.
- `</script` and `</style` in the bundles are escaped so an inline block
  cannot end early.
- The command reminds the user to use `--redact` before sharing.

## Consequences

- A Playwright test opens the report via `file://`, visits every view, and
  asserts zero CSP violations and zero network requests, with and without
  `--redact`.
- `frame-ancestors` cannot be set from a meta tag; hosting a report on a
  web server should add the header.
