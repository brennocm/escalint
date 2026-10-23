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

`go test -bench BenchmarkRun ./internal/engine/` runs the whole engine on
synthetic accounts (`internal/synth`, 10% of principals with a planted
escalation primitive on wildcard resources, a dense worst case). On a
4-core laptop: 2,000 principals in about 0.3 s, 20,000 in about 10 s.
Rules pre-filter candidates by action and resource before calling the
evaluator, composite rules only look at the actor's neighbors, and the
graph sorts adjacency lists lazily per node.
