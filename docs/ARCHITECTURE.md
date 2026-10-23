# Architecture

```mermaid
flowchart LR
  collect["collect (AWS SDK, read-only)"] --> snapshot[(snapshot.json)]
  snapshot --> load["snapshot: load, validate, resolve"]
  load --> policy["policy: typed documents"]
  load --> graph["graph: nodes, trust, assume, Tier 0"]
  policy --> eval["eval: decisions with traces"]
  eval --> graph
  graph --> rules["rules: escalation edges"]
  rules --> analysis["analysis: paths, tiers, blast, choke points, fix plan"]
  analysis --> engine["engine: findings"]
  engine --> out["text / json / sarif / dot / mermaid / analysis.json"]
  out --> ui["web UI (serve, HTML report, Pages)"]
```

## Go packages

| Package | Role |
| --- | --- |
| `internal/jsonx` | structural checks on untrusted JSON (depth, duplicate keys) |
| `internal/policy` | IAM policy documents with polymorphic elements |
| `internal/snapshot` | load authorization details or the envelope; diagnostics |
| `internal/arn` | ARN segments |
| `internal/match` | action and ARN wildcards (no regexps) |
| `internal/catalog` | embedded AWS action catalog |
| `internal/eval` | policy evaluation with SCPs, RCPs, trust and boundaries |
| `internal/graph` | can-act-as graph, environment for evaluations |
| `internal/analysis` | graph algorithms (below) |
| `internal/rules` | escalation, trust and parse rules; explicit registry |
| `internal/engine` | runs rules and analyses; findings (critical on a path to Tier 0), fix plan changes, rule selection |
| `internal/termsafe` | safe terminal output |
| `internal/attack`, `internal/detect` | embedded ATT&CK techniques and CloudTrail events per action (ADR 0021, 0022) |
| `internal/contract` | builds and encodes `analysis.json` (schema in `schema/`, ADR 0003) |
| `internal/redact` | per-run HMAC pseudonyms for `--redact` (ADR 0010) |
| `internal/config`, `internal/suppress` | `.escalint.yaml`; suppressions with reasons and expiry, groupings |
| `internal/diff` | compares two analyses by stable ID |
| `internal/report` | text, JSON, SARIF (ADR 0011), DOT and Mermaid writers |
| `internal/server` | `escalint serve` (ADR 0017) |
| `internal/htmlreport` | the single-file report with a hash-based CSP (ADR 0018) |
| `internal/collect` | read-only AWS collector (ADR 0020) |
| `internal/synth` | synthetic snapshots for tests, benchmarks and the demo |
| `internal/cli` | cobra commands; exit codes 0 / 1 / 2 |

## Analyses

| Analysis | File | Method |
| --- | --- | --- |
| Reach | `reach.go` | breadth-first search over escalation edges, depth limit 6, both directions |
| Paths | `paths.go` | Yen's k shortest simple paths (k = 3) to any tier0 sink, pruned by a reverse BFS from the sinks (ADR 0007) |
| Cycles | `scc.go` | iterative Tarjan strongly connected components (circular assume chains) |
| Tiers | `tiers.go` | Tier 0 from the probe set (graph builder), Tier 1 has a path, Tier 2 permission management / escalation primitive / sensitive read, Tier 3 rest (ADR 0008) |
| Blast radius | `blast.go`, `blastall.go` | reachable principals, reaches Tier 0, strongest capability class per service of the node and everything it reaches (transitively); computed for all principals at once on the strongly connected components with bitsets; capabilities use the evaluator in any-resource mode with a cache for identical policy sets |
| Choke points | `chokepoints.go` | number and share of enumerated paths through each edge |
| Fix plan | `fixplan.go` | greedy hitting set over enumerated paths (ADR 0009) |

All analyses are deterministic: neighbors in ID order, ties by ID, sorted
outputs; a test runs them 50 times and compares results.

## Engine

`engine.Run` builds the graph, drops assume edges when `EL-PE-014` is
disabled, applies the enabled rules (primitive pass, then composite pass),
enumerates paths, assigns tiers, computes blast radius for every principal,
choke points and the fix plan. Findings are per (rule, edge) for path rules
and raised to `critical` when the edge lies on an enumerated path; trust and
parse rules report findings directly. Findings sort by severity, rule ID and
finding ID; identical results collapse.

## Performance

`make bench-cli` times `analyze` and `scan` on synthetic accounts of 1k,
10k and 50k principals and reports peak memory; results are in
[benchmarks.md](benchmarks.md) (50,000 principals: about 28 s and 1.3 GB on
a 4-core laptop). `go test -bench BenchmarkRun ./internal/engine/` runs the
engine alone. Rules pre-filter candidates by action and resource before calling the
evaluator, composite rules only look at the actor's neighbors, and the
graph sorts adjacency lists lazily per node.

## Web UI

| Area | Files |
| --- | --- |
| Data | `web/src/data/load.ts` (inline, `serve`, demo datasets; schema version check), `indexes.ts` (by ID, adjacency, tier, account, findings and paths by node/edge) |
| State | `web/src/state/store.ts` (own store, ADR 0016), `route.ts` (hash router; all view state in the URL), `app.ts` (location binding) |
| Search | `web/src/search/fuzzy.ts`: prefix > word start > subsequence, ties by tier |
| Workers | `web/src/workers/rpc.ts` (typed calls with cancellation), `layout.worker.ts` |
| Shell | `web/src/shell/`: top bar, command palette, details panel, legend, help, states |
| Views | Overview, Atlas (WebGL2), Trace, Reach, Exposure, Findings, Fix plan, Diff, policy explainer (`web/src/views`, `web/src/explainer`) |
| Layout | `web/src/layout/`: force (Barnes–Hut), convex hull areas, label collision, spatial grid |

Rendering layers are described in ADR 0014, layout determinism in ADR 0015,
visual tests in ADR 0019. Performance budgets are checked by
`make web-perf` on synthetic analyses of 10,000 and 50,000 principals.

## Distribution

GoReleaser builds the release binaries (UI embedded), archives, SBOMs, the
signed checksum file and the signed multi-arch image; `action.yml` is a
composite GitHub Action that builds from its own source (ADR 0026). The
GitHub Pages demo is the same UI with synthetic datasets (`make demo`).
README media is regenerated with `make demo-media`.

## Adding a rule

1. Confirm the path and its prerequisites in the AWS documentation and on
   pathfinding.cloud; add or update its row in `docs/research.md` §7.
2. Create `internal/rules/el_pe_NNN.go` (or a trust rule in `trust.go`) with
   its metadata: ID, pathfinding.cloud IDs, category, severity, edge kind,
   required actions, prerequisites, ATT&CK techniques, status.
3. Register it in `internal/rules/registry.go` (explicit, no `init`).
4. Add fixtures under `internal/rules/testdata/<ID>/vulnerable/` and
   `.../safe/`; the harness also checks deny, boundary, SCP and conditional
   variants and multiple occurrences.
5. Write `docs/rules/<ID>.md` (description, why it matters, attack chain,
   vulnerable and fixed policy, references); it is embedded for `rules explain`.
6. Make `examples/vulnerable-account` trigger it and keep
   `examples/hardened-account` clean; run `make gen-docs` (coverage and the
   README table) and `make gen` if CloudTrail or ATT&CK data changed.

## Adding a view

1. A route in `web/src/state/route.ts` with all its state in the URL.
2. Pure logic (layout, scales, selectors) in `web/src/layout`,
   `web/src/data` or the view's `model.ts`, with unit tests.
3. The component in `web/src/views/<view>/`, colors only from design tokens.
4. An equivalent table or list, keyboard navigation, `aria-live` for
   selection changes, `prefers-reduced-motion` respected.
5. Component test, E2E and axe in both themes (`tests/e2e/fixtures.ts`
   `views()`), visual baselines (`make web-visual-update` in the Playwright
   container).
6. SVG or PNG export if the view is graphical (`web/src/views/export.ts`).
7. Document it here and in `docs/design.md`; register it in
   `web/src/views/registry.tsx`.
