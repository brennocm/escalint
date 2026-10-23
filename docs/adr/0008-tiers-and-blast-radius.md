# 0008 — Tiers and blast radius

Status: Proposed (Phase 0 checkpoint)

## Context

The UI and the severity model need a precise notion of "admin". Heuristics such as
counting wildcards (used by earlier tools) misclassify principals restricted by
permissions boundaries or SCPs, and miss admins built from many narrow statements.

## Decision

**Tier 0 (effective admin, per account).** P is Tier 0 when the evaluator returns
`Allow` for every action of the admin probe set on representative resources of P's
own account:

- IAM permission-management primitives on `arn:aws:iam::<account>:*`:
  `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:AttachGroupPolicy`,
  `iam:PutUserPolicy`, `iam:PutRolePolicy`, `iam:PutGroupPolicy`,
  `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey`,
  `iam:PassRole`, `iam:DeleteRolePermissionsBoundary`,
  `iam:DeleteUserPermissionsBoundary`, `sts:AssumeRole`;
- one witness per sensitive class on `*`: `s3:GetObject`, `kms:Decrypt`,
  `secretsmanager:GetSecretValue`, `ec2:RunInstances`.

If any probe is `Conditional` and none is denied, P is Tier 0 with `tier_conditional`.

**Tier 1:** P has at least one enumerated path to a `tier0_sink`.
**Tier 2:** no path, but P has an action annotated `IsPermissionManagement` in any
service, or a sensitive-read witness on `*`.
**Tier 3:** everything else.

**Blast radius** is a vector, never a single number:
`reachable_principals` (BFS, depth limit 6), `reaches_tier0`, and the services per
capability class (`permission_management`, `write`, `read`, `list`) that P can use
directly or through reachable principals. No derived score in v1.

## Alternatives considered

- *`*:*` on `*` only*: misses admins with `NotAction` denies on billing; flags admins
  neutered by boundaries.
- *All `IsPermissionManagement` actions of IAM*: too strict; a policy missing one
  obscure action would stop being admin, and the catalog changes monthly.
- *Self-escalation folded into Tier 0 (PMapper style)*: hides the escalation edge the
  user must fix; we keep it as an explicit edge to the sink instead.

## Consequences

- Tier 0 is stable across catalog updates (fixed probe set, versioned here).
- `iam:*`-only principals are Tier 1 with a one-hop self-escalation path, which keeps
  the fix visible.
- Session policies are not modeled, so a role used only with restrictive session
  policies may be over-classified (documented in `docs/research.md` §5).
