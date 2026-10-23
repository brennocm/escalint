# 0019 — Visual tests in CI

Status: Accepted

## Context

Screenshots differ across operating systems, font stacks and GPUs. The UI
uses only self-hosted fonts, but WebGL output depends on the GPU driver.

## Decision

- One project, Chromium, 1280×800, device scale 1, reduced motion, both
  color schemes, for every view (`web/tests/visual`, config
  `playwright.visual.config.ts`).
- Data and layout are deterministic (ADR 0015); the Atlas WebGL canvas is
  masked, its Canvas 2D overlay is compared.
- Tolerance: `maxDiffPixelRatio: 0.02`.
- CI runs the suite in the official Playwright container of the pinned
  version, the same browser build that produced the baselines.
- Baselines are generated only inside that container and updated
  deliberately: `make web-visual-update` runs it with Docker; without Docker,
  the manual `visual-baselines` workflow produces them as an artifact. The
  images are reviewed in the pull request.
- Accessibility (axe, WCAG 2.2 AA tags) and functional E2E run in the main
  E2E suite on Chromium, Firefox and WebKit; axe runs in Chromium only.

## Consequences

- A rendering change shows up as an image diff to review rather than a
  silent regression.
- Baselines generated on another platform may need a refresh the first
  time CI runs; the job uploads the actual images to make that easy.
