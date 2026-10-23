# 0026 — Release artifacts and the GitHub Action

Status: Accepted

## Context

escalint runs on machines and CI jobs that hold a map of who can become
administrator. Users need a way to verify that what they run is what this
repository built, and the GitHub Action must work for every commit (including
the self-test on unreleased commits).

## Decision

- **Releases** are built by GoReleaser from a tag: binaries for
  linux/darwin/windows × amd64/arm64 with the UI embedded (`CGO_ENABLED=0`,
  `-trimpath`, commit timestamp as mtime), archives, a source tarball, SBOMs
  (syft) for every archive and the source, `checksums.txt` signed keyless with
  cosign (Sigstore bundle), and a build provenance attestation over the
  checksums (`actions/attest-build-provenance`).
- **Image:** `ghcr.io/brennocm/escalint`, multi-arch, on
  `gcr.io/distroless/static-debian12:nonroot` pinned by digest, signed with
  cosign. `Dockerfile.goreleaser` copies the binaries GoReleaser built;
  `Dockerfile` builds the same image from source (Node stage, Go stage,
  distroless) and is exercised by the `docker` CI job.
- **GitHub Action:** a composite action that builds escalint from the
  action's own source with `-tags noui` (scan and diff need no UI). The source
  is pinned by the ref the caller uses, ideally a commit SHA, so the action
  never downloads an unsigned binary or depends on a release existing.
  Inputs reach the shell only through environment variables (no template
  injection). The report step always writes the report (`--fail-on none`); a
  separate gate step applies `fail-on`, against `baseline` with `escalint
  diff` when one is given, so SARIF can be uploaded even when the gate fails.

## Consequences

- The action costs a Go build (about a minute without cache) per run.
- The gate prints findings to the job log and summary; `redact: true` applies
  to both the report and the gate.
- Verification commands are in the README and in the release notes.
