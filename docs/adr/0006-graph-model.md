# 0006 — Graph model: node and edge kinds

Status: Accepted

## Context

Escalation analysis needs one relation that every path algorithm can use.
IAM offers many ways for one principal to obtain another's privileges, and
some of them only work in combination.

## Decision

- One directed relation: X → Y means "X can obtain Y's privileges (or
  more)". Every escalation becomes a path to a virtual `tier0_sink` per
  account ("effective admin").
- Node kinds: `user`, `role`, `group` (from authorization details),
  `service`, `external_account`, `federated`, `any_principal` (principals
  named in trust policies) and `tier0_sink`.
- Edge kinds: `assume`, `trust`, `credential`, `modify_permissions`,
  `modify_trust`, `passrole_compute`, `update_code`, `admin` (Tier 0
  principal → sink) and the structural `member_of`.
- `modify_permissions` on another principal is not an act-as edge by
  itself: combined with an act-as edge it becomes a composite edge to the
  sink; otherwise it is kept as a **latent** edge (reported, never used by
  path search).
- Every edge keeps the rules that produced it, the evidence statements, its
  status (`allowed` / `conditional`), the unevaluated condition keys and the
  unverified prerequisites. Parallel variants of the same (from, to, kind)
  merge into one edge.

The detailed semantics are in docs/research.md §6.

## Alternatives considered

- *One node per policy or permission:* closer to IAM's data model, but
  paths become long and unreadable and every algorithm needs special cases.
- *Separate graphs per edge kind:* hides combinations, which are the point.

## Consequences

- Paths read as "who becomes whom"; fixes target single edges.
- Multi-hop "modify then reach" combinations beyond the pathfinding.cloud
  cases are reported as latent edges, not as paths (documented limitation).
