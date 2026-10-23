# 0004 — Policy evaluation model and what v1 does not model

Status: Accepted

## Context

escalint must decide, without calling AWS, whether a principal can perform
an action on a resource, and explain the decision. AWS documents the logic
in pieces (single account, cross-account, SCPs, RCPs, boundaries, trust
policies); docs/research.md §2 consolidates it with sources.

## Decision

`internal/eval.Evaluate` implements:

1. **Explicit deny** in any applicable policy (RCP, SCP, resource, identity,
   boundary) wins.
2. **RCPs** of the resource account, only for RCP-covered services
   (`RCPApplies`), never for service-linked roles: every organization level
   needs an allow.
3. **SCPs** of the principal account, never for service-linked roles or the
   management account (the caller passes no chain): every level needs an
   allow.
4. **Resource-based policy** (v1: role trust policies), with the same-account
   rules of research §2.4: a trust naming the user grants alone; naming the
   role needs the role's boundary; `"*"` grants alone and ignores the
   boundary (E37); naming the account needs the identity policies.
5. **Identity policies** and the **permissions boundary**.
6. **Cross-account:** both the trust and the caller's identity (+ boundary)
   must allow. Principals outside the snapshot (services, federated users,
   external accounts, anyone) are judged by the trust alone.

Each gate is three-valued (allow, no allow, unknown); the decision is
`Allow`, `ExplicitDeny`, `ImplicitDeny` or `Conditional`. The result keeps
every matching or conditional statement as a trace step and the decisive
step, so reports can say "allowed by statement Sid=X in policy P".

`iam:PassRole` across accounts is always denied (E33).

**Not modeled in v1** (research §5): session policies and session tags,
resource policies other than trust, KMS grants, root users, request-time
conditions, Identity Center assignments, role chaining limits.

## Alternatives considered

- *IAM Policy Simulator:* needs credentials and network, does not model
  SCP/RCP combinations faithfully, and cannot run in a static report.
- *Reuse an existing evaluator library:* none in Go covers RCPs, SCP levels
  and trust rules together with a trace we can show in the UI.

## Consequences

- Edge cases E01–E37 are unit tests named after the documentation source;
  invariants (deny wins, limits never grant, order independence,
  determinism) are property tests.
- The optional differential test against the Policy Simulator is not part of
  CI: it needs a real AWS account, which requires explicit approval.
