# 0013 — Frontend stack and dependency budget

Status: Accepted (versions verified 2026-10-23)

## Context

The UI renders large graphs and must be fast, accessible, fully offline and
safe against hostile data in snapshots. Every runtime dependency ends up in the
self-contained HTML report and widens the supply-chain surface.

## Decision

- **Runtime dependencies (budget):** `react`, `react-dom`, `sigma`,
  `graphology`, `graphology-layout-forceatlas2`, `elkjs`. Anything else needs a
  new ADR. Phase 1 only uses `react` and `react-dom` (19.3.1).
- **Language:** TypeScript **6.0.x** with `strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, `noImplicitOverride`.
  TypeScript 7 (the native port) is the current `latest`, but
  `typescript-eslint` 8.72 declares `typescript >=4.8.4 <6.1.0`, and the
  type-checked lint rules are a core quality gate. We move to 7 when
  typescript-eslint supports it; Dependabot ignores TS minor/major bumps until
  then.
- **Lint:** ESLint **9** (flat config) because `eslint-plugin-jsx-a11y` 6.10
  supports ESLint up to 9; `typescript-eslint` `strictTypeChecked` +
  `stylisticTypeChecked`, `react-hooks`, `jsx-a11y` strict, Prettier.
  `no-restricted-syntax` forbids `dangerouslySetInnerHTML`, `innerHTML`,
  `outerHTML`, `insertAdjacentHTML` and `document.write`; `no-eval`,
  `no-implied-eval` and `no-new-func` are errors.
- **Build:** Vite 8 with `base: './'` so one build works under `serve`, a
  GitHub Pages sub-path and `file://`.
- **Tests:** Vitest 5 + `happy-dom` + Testing Library; Playwright 1.64 on
  Chromium, Firefox and WebKit.
- **Tooling:** pnpm (pinned in `packageManager`), Node.js LTS 24 in `.nvmrc`.

### Dev dependencies and why

| Package | Why |
| --- | --- |
| `typescript` | type checking (`tsc --noEmit`) |
| `vite`, `@vitejs/plugin-react` | dev server and production build |
| `vitest`, `@vitest/coverage-v8`, `happy-dom`, `@testing-library/react` | unit and component tests with coverage |
| `@playwright/test` | E2E, later visual, a11y and performance tests |
| `eslint`, `@eslint/js`, `typescript-eslint`, `eslint-plugin-react-hooks`, `eslint-plugin-jsx-a11y`, `eslint-config-prettier`, `globals` | linting |
| `prettier` | formatting |
| `@types/react`, `@types/react-dom` | React types |

## Alternatives considered

- *TypeScript 7 without type-aware lint:* loses the rules that catch unsafe
  `any` flows and floating promises.
- *ESLint 10:* blocks `jsx-a11y`, which we need for WCAG 2.2 AA.
- *jsdom instead of happy-dom:* slower; happy-dom is enough for component tests,
  and real-browser behavior is covered by Playwright.

## Consequences

- We run one major behind on TypeScript for now; revisit when
  typescript-eslint adds TS 7 support.
- WebKit E2E needs system libraries (`playwright install --with-deps` in CI).
