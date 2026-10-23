# 0002 — Monorepo with the UI embedded via `embed` and a `noui` build tag

Status: Accepted

## Context

escalint ships one binary that analyzes snapshots and serves a web UI on
loopback. The frontend is TypeScript built with Vite; the engine is Go.
Contributors working only on the engine should not need Node.js.

## Decision

- One repository: Go module at the root, frontend in `web/`.
- The compiled frontend (`web/dist`) is embedded with `//go:embed all:dist`.
  Because `//go:embed` cannot reference parent directories, the directive
  lives in a small Go package in `web/` (`github.com/brennocm/escalint/web`),
  which `internal/server` imports.
- With the build tag `noui`, `web/embed_noui.go` embeds a stub page
  (`web/noui/index.html`) that explains how to build the UI. Tests, linters and
  `govulncheck` always run with `-tags noui`, so `go build`/`go test` work on a
  clean checkout.
- Release and CI `build` jobs build the frontend first and then the binary
  without the tag.

## Alternatives considered

- *Copy `web/dist` into `internal/server/` before building:* hides a build step
  and leaves a generated copy next to source.
- *Serve the UI from disk:* breaks the single-binary promise.
- *Commit `web/dist`:* noisy diffs and a risk of shipping a stale UI.

## Consequences

- `go build ./...` without the tag fails until `make web-build` has run; the
  Makefile `build` target checks this and prints the fix.
- The stub keeps `serve` testable in Go-only CI jobs.
