# Contributing

Thanks for considering a contribution. This document explains how to build,
test and propose changes.

## Requirements

- Go (version in `go.mod`; the `toolchain` line downloads it automatically).
- Node.js LTS (version in `.nvmrc`) and pnpm (version in `web/package.json`).
- `golangci-lint` and `govulncheck` for `make lint` and `make vuln`.

Go work does not require Node.js: tests build with `-tags noui`.

## Common commands

```sh
make test-race      # Go tests with the race detector
make lint           # go vet, golangci-lint, gofumpt
make cover-check    # coverage with per-package targets
make web-install    # frontend dependencies
make web-lint web-test web-e2e
make web-build build
```

Run `make help` for the full list. Every CI step maps to a Makefile target.

## Pull requests

- Keep commits small and atomic, using
  [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(eval): …`, `fix(web/atlas): …`). Each commit must build and pass tests.
- Add or update tests with every change. Rules need positive, negative,
  deny-blocked, boundary-blocked, SCP-blocked and conditional cases.
- Non-obvious decisions get an ADR in `docs/adr/`.
- Never commit real account data, account IDs or credentials, including in
  fixtures. Use `111111111111`, `222222222222` and `999999999999` (external).
- Claims about AWS behavior must link to the official documentation.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
