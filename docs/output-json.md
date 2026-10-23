# JSON output of `escalint scan`

`escalint scan --format json` prints a findings-oriented document. Its
objects (`findings[]`, `paths[]`, `fix_plan[]`, `suppressions[]`,
`snapshot`, `generator`) are the same as in `analysis.json`, whose JSON
Schema is `schema/analysis.v1.schema.json` (`escalint schema` prints it).
Use `escalint analyze` when you need the whole graph.

```jsonc
{
  "schema_version": "1",
  "kind": "escalint.scan",
  "generator": { "name": "escalint", "version": "v0.1.0", "commit": "…" },
  "snapshot": { "format": "envelope", "collected_at": "2026-10-01T00:00:00Z", "partition": "aws",
                "accounts": ["111111111111"], "redacted": false, "organization": null },
  "summary": { "critical": 1, "high": 4, "medium": 0, "low": 0, "info": 0, "suppressed": 0, "paths": 1 },
  "findings": [{
    "id": "f_f3a444cda88ece4f",          // stable across runs (ADR 0010)
    "rule_id": "EL-PE-020",
    "severity": "critical",              // raised to critical on a path to Tier 0
    "title": "Modify a role's permissions and rewrite its trust",
    "message": "arn:aws:iam::111111111111:user/attacker can act as …",
    "node_id": "n_…", "edge_id": "e_…", "path_id": "p_…",
    "latent": false,                     // true: needs another step to be usable
    "location": { "account": "111111111111", "entity": "arn:…:user/attacker",
                  "policy": "inline:arn:…:user/attacker/p", "statement_index": 0, "path": "", "line": 92 },
    "remediation": "…",
    "suppressed": null                   // or { "reason", "expires", "source" }
  }],
  "paths": [{ "id": "p_…", "source": "n_…", "target": "n_…", "edges": ["e_…"], "nodes": ["n_…", "n_…"],
              "length": 1, "status": "allowed", "severity": "critical" }],
  "fix_plan": [{ "order": 1, "edge_id": "e_…", "change": "Remove iam:AttachRolePolicy … from statement #0 of …",
                 "target": "inline:arn:…:user/attacker/p#0", "paths_cut": ["p_…"] }],
  "suppressions": [],
  "notes": []
}
```

## Fields worth knowing

- `location.policy` uses the evidence notation: a managed policy ARN,
  `inline:<owner ARN>/<policy name>`, `trust:<role ARN>`, or
  `rewritten-trust:<role ARN>` (the trust policy an attacker would write).
- `location.statement_index` is `-1` when the finding is not tied to one
  statement; `location.line` is the line in the snapshot file, or `null`.
- `paths[].status` is `conditional` when a condition key could not be
  evaluated or a prerequisite (for example "an ECS cluster exists") could
  not be verified; such paths are reported with severity `high`.
- With `--redact`, every identifier (accounts, names, ARNs, tags, IDs) is a
  pseudonym that is stable within one run only.

Exit codes: `0` no unsuppressed finding at or above `--fail-on`, `1` such
findings exist, `2` usage or runtime error.
