# 0016 — Own store instead of a state library

Status: Accepted

## Context

The UI state is small (route, selection, filters, camera, theme, dialogs)
and must round-trip through the URL. The data (analysis.json and its
indexes) is immutable after loading.

## Decision

- A 40-line external store (`web/src/state/store.ts`): an immutable state
  object, `set(update)` replacing it, listeners notified on change, read by
  React through `useSyncExternalStore`.
- Derived data comes from memoized selectors (`memo`, `memo2`: last input
  by reference), which is enough with immutable state.
- The route is the source of truth for what is shown; `bindLocation` syncs
  it with `location.hash` (navigation pushes history entries; camera moves
  replace them). Invalid links degrade to the Overview with a notice.
- Indexes (by ID, adjacency in/out, by tier, by account, findings and paths
  by node and edge) are built once per analysis (`web/src/data/indexes.ts`).

## Alternatives considered

- *Redux Toolkit, Zustand, Jotai:* each adds a dependency and concepts for
  a state shape this small; the dependency budget (ADR 0013) prefers none.
- *React context with useReducer:* re-renders every consumer on any change.

## Consequences

- No state dependency; behavior is covered by unit tests (round-trip of
  500 random routes, location binding, memoization).
