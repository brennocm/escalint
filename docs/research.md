# escalint — Phase 0 research

Status: **proposal, awaiting approval** (Phase 0 checkpoint).
Research date: 2026-10-23. Every claim below links to the source it was verified against.
Anything not confirmed in official documentation is marked **`experimental`**.

---

## 1. Sources

| Topic | Source |
| --- | --- |
| Evaluation logic (single account) | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html |
| Evaluation flow charts (user / role) | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html |
| Cross-account evaluation | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html |
| Cross-account resource access | https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html |
| SCPs | https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html |
| SCP inheritance | https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html |
| RCPs | https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html |
| `Principal` | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `NotPrincipal` | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html |
| `NotAction` | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html |
| `Resource` / wildcards | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html |
| Condition operators | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html |
| Set operators | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html |
| `iam:PassRole` | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html |
| `sts:AssumeRole` | https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html |
| Service-linked roles | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create-service-linked-role.html |
| `GetAccountAuthorizationDetails` | https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html |
| `RoleDetail` / `UserDetail` / `ManagedPolicyDetail` | https://docs.aws.amazon.com/IAM/latest/APIReference/API_RoleDetail.html · [UserDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UserDetail.html) · [ManagedPolicyDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ManagedPolicyDetail.html) |
| Service reference (machine readable) | https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html |
| GitHub OIDC in AWS | https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws |
| GitHub Actions billing | https://docs.github.com/en/billing/concepts/product-billing/github-actions |
| GitHub-hosted runners | https://docs.github.com/en/actions/reference/runners/github-hosted-runners |
| pathfinding.cloud | https://github.com/DataDog/pathfinding.cloud (commit `ecc3d092e7e409497474c8d39eb92f61810d815f`, 2026-10-09) |

---

## 2. Evaluation semantics implemented by `internal/eval`

### 2.1 Order (single account)

The AWS documentation describes this order ([denyallow]):

1. **Explicit deny** in *any* applicable policy (SCP, RCP, resource-based, identity, boundary, session) → **Deny**.
2. **RCPs** (of the account that owns the resource; only for supported services) — no applicable `Allow` → Deny.
3. **SCPs** (of the account that owns the principal) — no applicable `Allow` → Deny.
4. **Resource-based policy** — for same-account requests, an `Allow` that names the IAM **user** (or a session) directly can yield `Allow` even with an implicit deny in identity/boundary. An `Allow` naming an IAM **role ARN** is still limited by an implicit deny in the role's **boundary** (and session policy), but not by the identity policy.
5. **Identity-based policies** (user inline + managed + groups' inline + managed; role inline + managed) — no `Allow` → Deny.
6. **Permissions boundary** — present and no `Allow` → Deny.
7. **Session policy** — v1 does not model sessions (see §5).

> Correction (Phase 4, 2026-10-23): the Phase 0 table said a `"*"` trust needs an identity allow in the same account. The Principal documentation says the opposite; the row above and edge case E37 follow the documentation.

> Note on the order in the spec (§3.4 of `project.md`): it listed SCP before RCP and boundary before identity. Steps 2–6 are a logical **AND** (apart from the resource-policy shortcut in step 4), so the order only changes the *trace*, never the decision. The trace will follow the AWS order above.

The evaluator returns one of `Allow`, `ExplicitDeny`, `ImplicitDeny`, `Conditional` plus a trace: every policy/statement consulted, the step it belongs to, and which statement decided.

### 2.2 Organizations

- **SCP inheritance:** an `Allow` must exist at **every level** (root, each OU on the path, the account); a `Deny` at any level denies ([scps_evaluation]).
- **RCP inheritance:** same model; `RCPFullAWSAccess` is attached everywhere and cannot be detached ([denyallow], [rcps]).
- SCPs **do not affect** principals of the **management account** nor **service-linked roles** ([scps]).
- RCPs **do not affect** resources of the management account, calls made by service-linked roles, nor the trust policy of service-linked roles ([rcps]).
- RCPs only apply to a fixed list of services. **`sts` is in the list; `iam` is not** ([rcps]). Consequence: an RCP can block `sts:AssumeRole` on a role, but never `iam:*` actions. The list is embedded as data with its verification date.
- SCPs don't apply to principals of accounts outside the organization; RCPs apply to all callers (including external ones) on resources of member accounts ([rcps]).

### 2.3 Cross-account

Two evaluations; the request is allowed only if both allow ([cross-account]): the caller's account (identity, boundary, SCPs of the caller's account) **and** the resource account (resource policy, RCPs of the resource account). For `sts:AssumeRole`, the identity policy of the caller **must** allow it ([AssumeRole]).

### 2.4 Role trust policies (the resource policy that matters in v1)

From [AssumeRole]: in the same account, a user can assume a role if **either** (a) the identity policy allows `sts:AssumeRole` *and* the trust policy trusts the account, **or** (b) the trust policy names the user directly — "When a resource-based policy grants access to a principal in the same account, no additional identity-based policy is required."

Combined with step 4 of §2.1, the `assume` edge X → role Y is decided as:

| Trust policy names… | Same account | Cross-account |
| --- | --- | --- |
| X's ARN, X is a **user** | allowed by trust alone (identity and boundary not needed); SCP of X's account and RCP of Y's account still apply | trust **and** X's identity must allow |
| X's ARN, X is a **role** | trust + X's **boundary** must allow (identity not needed) | trust **and** X's identity (+ boundary) |
| X's account (`"123…"` or `:root`) | trust **and** X's identity (+ boundary) | trust **and** X's identity (+ boundary) |
| `"*"` / `{"AWS":"*"}` | allowed by trust alone for in-account users and roles, and **not** limited by an implicit deny in a boundary ([principal]: "For IAM users and role principals within your account, no other permissions are required"; "Permissions boundaries … do not limit permissions granted using … a wildcard (*) in the Principal element") | trust **and** the caller's identity (+ boundary) |

Other facts:
- Principals in trust policies are **converted to unique IDs** when saved; if the principal was deleted, the trust shows an ID like `AROA…`/`AIDA…` that matches nothing ([principal]).
- Wildcards **cannot** match part of a principal ARN; only the full `"*"` is valid ([principal]).
- Groups cannot be principals ([principal]).
- `Service` principal can't be `"*"` ([principal]).
- `NotPrincipal` is **not** allowed in trust policies, identity policies, SCPs or RCPs; it is only valid with `Deny` ([notprincipal]). v1 parses it (to report) but never needs to evaluate it in an allow path.
- OIDC federated principals (`Federated: arn:…:oidc-provider/…` or the built-ins) and SAML principals are only valid in trust policies ([principal]).

### 2.5 `iam:PassRole`

- It is a permission, not an API call ([passrole]); checked by the service when the role ARN is passed.
- Only same-account roles can be passed ([passrole]).
- Scoped by `Resource` and by the condition key `iam:PassedToService` ([passrole]). The engine knows which service each rule passes to, so this key is **evaluated** (see §2.7).
- Passing a service-linked role also requires `iam:PassRole` ([passrole]).

### 2.6 Matching

- **Actions:** case-insensitive; `*` and `?` wildcards; `service:*`; `*` alone. `NotAction` with `Allow` grants every applicable action not listed, **including other services** when `Resource` is `*` ([notaction]).
- **Resources:** ARN matched **segment by segment** (6 colon-separated segments); `*`/`?` within a segment; `*` matches `/`; **a `*` as the last character of a segment can expand beyond the colon boundary**; no wildcard in the service segment ([resource]). Resource names are case-sensitive ([resource]: "the IAM user name is case sensitive"). `NotResource` inverts.
- **Policy variables** (`${aws:username}` etc.): v1 substitutes `${aws:username}`, `${aws:userid}`, `${aws:PrincipalAccount}`… only where the value is known statically (the principal under evaluation); any other variable → `Conditional`.

### 2.7 Conditions in v1

Proposal: a **minimal set** of condition keys whose value is known statically; everything else makes the statement `Conditional`.

| Key | Value source | Why safe |
| --- | --- | --- |
| `aws:PrincipalArn` | the principal under evaluation | fixed by the snapshot |
| `aws:PrincipalAccount` | idem | fixed |
| `aws:PrincipalOrgID` | organization data in the snapshot; unknown → `Conditional` | fixed when org data present |
| `aws:PrincipalIsAWSService` | `true` only for `service` nodes | fixed |
| `iam:PassedToService` | the service principal of the rule being checked | fixed by the rule |
| `aws:username`, `aws:userid` | the IAM user under evaluation (also used by policy variables such as `${aws:username}`) | fixed by the snapshot (added in Phase 4) |

Deliberately **not** evaluated (become `Conditional`):
- `aws:PrincipalTag/*`, `aws:ResourceTag/*` — session tags can override principal tags; tags can be changed with `iam:Tag*`.
- `aws:MultiFactorAuthPresent`, `aws:SourceIp`, `aws:RequestedRegion`, `aws:CurrentTime`, `sts:ExternalId`, OIDC `…:sub`/`…:aud` — request-time values.

Operator semantics implemented for the evaluated keys: all String/ARN operators, `…IfExists`, `Null`, `ForAnyValue:`/`ForAllValues:` (including "ForAllValues is true when the key is missing", [set-operators]), and "negated operator with missing key is true" ([condition-operators]). Multiple keys in one block = AND; multiple values for one key = OR; multiple operators = AND ([condition-operators]).

**Conditional policy (ADR 0005):**
- `Allow` statement with an unevaluated condition → contributes a `Conditional` allow.
- `Deny` statement with an unevaluated condition → may or may not apply → the decision cannot be `Allow`, it becomes `Conditional` (never silently `Deny`). Rationale: rule 6 of the collaboration rules ("when in doubt, report").
- The edge keeps `conditions_unevaluated` with the keys, and the UI shows why.

---

## 3. Edge-case table (each row becomes a named test in Phase 4)

| # | Case | Expected | Source |
| --- | --- | --- | --- |
| E01 | `Allow` + `NotAction: iam:*` + `Resource: *`; request `s3:GetObject` | Allow | [notaction] |
| E02 | E01; request `iam:PutUserPolicy` | ImplicitDeny | [notaction] |
| E03 | `Allow` + `NotAction: iam:*` + `Resource: arn:aws:s3:::*`; request `ec2:RunInstances` on `*` | ImplicitDeny (resource scopes the statement) | [notaction] |
| E04 | `Deny` + `NotAction: iam:*`; request `iam:ListUsers` allowed elsewhere | Allow (deny does not match) | [notaction] |
| E05 | Identity allows `iam:*`, boundary allows only `s3:*`; request `iam:PutRolePolicy` | ImplicitDeny (boundary) | [denyallow] |
| E06 | Boundary contains `Deny iam:*`; identity allows `*` | ExplicitDeny | [denyallow] |
| E07 | SCP at OU allows only `ec2:*`; root has FullAWSAccess; identity `*`; request `iam:CreateAccessKey` | ImplicitDeny (SCP level without allow) | [scps_evaluation] |
| E08 | SCP denies `iam:*`; principal in **management account** | SCP ignored → Allow | [scps] |
| E09 | SCP denies `iam:*`; principal is a **service-linked role** (`/aws-service-role/`) | SCP ignored | [scps] |
| E10 | RCP denies `sts:AssumeRole` from outside org; external principal assumes member-account role | ExplicitDeny | [rcps] |
| E11 | RCP with `Deny iam:*` | no effect (iam not RCP-supported) | [rcps] |
| E12 | RCP on management-account role | no effect | [rcps] |
| E13 | Same account: trust names user U; U has no identity policy | Allow | [AssumeRole] |
| E14 | Same account: trust names role R; R's boundary doesn't allow `sts:AssumeRole` | ImplicitDeny | [denyallow] |
| E15 | Same account: trust names role R; R has no identity allow, no boundary | Allow | [denyallow] |
| E16 | Same account: trust names account root; U without identity allow | ImplicitDeny | [AssumeRole] |
| E17 | Cross-account: trust names U's ARN; U without identity allow | ImplicitDeny | [cross-account] |
| E18 | Trust `"Principal":"*"` + `StringEquals aws:PrincipalOrgID o-x`; org data present, caller in org | Allow; external caller → ImplicitDeny | [principal] |
| E37 | Same account: trust `"Principal":"*"` (no condition); caller has no identity allow and a boundary without sts:AssumeRole | Allow (wildcard grants need no identity allow and ignore the boundary's implicit deny) | [principal] |
| E19 | E18 without org data in snapshot | Conditional (`aws:PrincipalOrgID`) | §2.7 |
| E20 | Trust with principal unique ID `AROA…` (deleted role) | matches nothing; reported as info | [principal] |
| E21 | `Principal: {"AWS":"arn:aws:iam::111111111111:role/*"}` | invalid (partial wildcard); parse finding, never matches | [principal] |
| E22 | Action `iam:*Policy*` matches `iam:PutRolePolicy` and `iam:AttachUserPolicy` | match | [catalog] |
| E23 | Action `IAM:putrolepolicy` vs `iam:PutRolePolicy` | match (case-insensitive) | [resource]/[catalog] |
| E24 | Resource `arn:aws:iam::111111111111:user/Bob` vs `…:user/bob` | no match (case-sensitive) | [resource] |
| E25 | Resource `arn:aws:s3:::bucket/*/test/*` vs `bucket/1/2/test/x` | match (`*` matches `/`) | [resource] |
| E26 | Resource `arn:aws:iam::*` vs `arn:aws:iam::111111111111:role/x` | match (trailing `*` crosses colons) | [resource] |
| E27 | `Deny` with `aws:MultiFactorAuthPresent` (unevaluated) over an Allow | Conditional | §2.7 |
| E28 | `Allow` with `StringNotEqualsIfExists` on missing key | condition true | [condition-operators] |
| E29 | `ForAllValues:StringEquals` on missing key | true (overly permissive) | [set-operators] |
| E30 | `StringNotLike` on missing key | true | [condition-operators] |
| E31 | `NotPrincipal` + `Allow` | unsupported → parse finding | [notprincipal] |
| E32 | `iam:PassRole` with `iam:PassedToService: ec2.amazonaws.com`; rule passes to `lambda.amazonaws.com` | ImplicitDeny | [passrole] |
| E33 | `iam:PassRole` on a role in another account | never allowed (same-account only) | [passrole] |
| E34 | Policy document URL-encoded (SDK) vs JSON object (CLI) | both parse to the same model | [authz-details] |
| E35 | `Action`/`Resource`/`Principal`/`Condition` values as string vs list | equivalent | [principal] |
| E36 | SCP present but snapshot has no OU tree | Conditional for actions the SCP could restrict (unknown attachment) | §5 |

---

## 4. Tier 0 (detail in `docs/adr/0008-tiers-and-blast-radius.md`)

**Definition.** A principal P is **Tier 0 (effective admin)** if, after full evaluation (identity ∩ boundary ∩ SCP, with denies), P is `Allow`ed — unconditionally — for **every** action in the *admin probe set* on a representative resource of its own account:

`A0 = { iam:AttachUserPolicy, iam:AttachRolePolicy, iam:AttachGroupPolicy, iam:PutUserPolicy, iam:PutRolePolicy, iam:PutGroupPolicy, iam:CreatePolicyVersion, iam:UpdateAssumeRolePolicy, iam:CreateAccessKey, iam:PassRole, sts:AssumeRole, iam:DeleteRolePermissionsBoundary, iam:DeleteUserPermissionsBoundary }` on `arn:aws:iam::<account>:*` (users, roles, groups, policies), plus one non-IAM witness per sensitive class (`s3:GetObject`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, `ec2:RunInstances`) on `*`.

Rationale: controlling all of IAM's permission-management primitives on every entity of the account is equivalent to admin (it can grant itself anything up to the SCP ceiling); the witnesses exclude "IAM-only" admins whose SCP blocks the data plane, which we classify Tier 1 instead.

- Any probe `Conditional` (and none denied) → Tier 0 with flag `tier_conditional`.
- Tier 0 is **per account**: admin of account A is Tier 0 in A only. The `tier0_sink` has one virtual node per account.

| Example | Tier |
| --- | --- |
| `AdministratorAccess` attached, no boundary, FullAWSAccess SCP | 0 |
| `{"Action":"*","Resource":"*"}` inline in a group the user is in | 0 |
| `AdministratorAccess` + boundary allowing only `s3:*` | not 0 (likely 2) |
| `AdministratorAccess` + SCP denying `iam:Attach*` | not 0 |
| `AdministratorAccess` with `Condition: aws:MultiFactorAuthPresent` | 0, `tier_conditional` |
| `iam:*` on `*` only | 0 only if SCP/identity also allow the witnesses; `iam:*` alone → Tier 1 (one hop: attach admin to self) |
| `NotAction: iam:*` on `*` (PowerUserAccess) | not 0; Tier 1 if it can `iam:PassRole` + compute to an admin role, else 2 |
| `iam:PutRolePolicy` on its own role only | Tier 1 (self-escalation edge to sink) |

**Tier 1** = has an enumerated path to a `tier0_sink`. **Tier 2** = no such path but has `IsPermissionManagement` on any service (from the catalog), an escalation primitive (any action required by a registered rule; needed because the service reference annotates `iam:PassRole` and `iam:CreateAccessKey` as Write), or a sensitive-read witness (`secretsmanager:GetSecretValue`, `kms:Decrypt`, `ssm:GetParameter*`, `s3:GetObject` on `*`). **Tier 3** = rest.

---

## 5. What v1 does NOT model (explicit)

1. **Session policies** and session tags (unknown statically). Effect: possible false positives; documented in each path ("assumes no session policy").
2. **Resource-based policies other than role trust**: S3, KMS key policies, Lambda function policies, Secrets Manager, SQS/SNS. (v0.2 idea.) Effect: KMS-dependent or bucket-policy-blocked paths may be over-reported; cross-account grants via resource policies are not edges.
3. **Root user** of each account (not in the snapshot).
4. **Request-time conditions** (MFA, IP, region, time, VPC endpoint, tags) — become `Conditional`.
5. **IAM Identity Center** permission sets as such (they appear as roles `AWSReservedSSO_*`; their assignment to users is out of scope).
6. **Role chaining limits**, maximum session duration, `sts:TagSession`/`sts:SetSourceIdentity` requirements.
7. **Service-specific authorization quirks** beyond PassRole (e.g., KMS grants, ECS task roles via `ecs:ExecuteCommand` without inventory).
8. **Permissions granted via resource policies to the account** (`Principal: {"AWS": "<acct>"}` on non-IAM resources).
9. **SCPs/RCPs without the OU tree:** if the snapshot contains policies but not their attachment points, every action an SCP could restrict becomes `Conditional` (E36).
10. **Multi-hop "modify then reach"**: `X` can modify `Y`'s permissions and reaches `Y` only through a chain of ≥ 2 hops. v1 composes only the direct cases defined by pathfinding.cloud (iam-014…021). The uncomposed `modify_permissions` edge is still emitted and reported (`EL-PE-…` high), never dropped.

---

## 6. Graph model (ADR 0006)

Edge semantics: **X → Y = "X can obtain Y's privileges (or more)"**.

Adjustments proposed to the skeleton in `project.md` §3.4:

- New edge kind **`admin`**: structural, from every Tier-0 principal to its account's `tier0_sink`. Paths end at the sink, so Tier-0 nodes and self-escalations share one target.
- **Self-escalation** edges (`modify_permissions` on self, own group or an attached policy) go **directly to `tier0_sink`**.
- `modify_permissions` / `modify_trust` / `credential` on *another* principal Y:
  - `credential` X → Y (user) and `modify_trust` X → Y (role) are act-as edges by themselves.
  - `modify_permissions` X → Y is **not** an act-as edge. If an act-as edge X → Y also exists, the builder emits a composite edge X → `tier0_sink` (pathfinding iam-014…021) with both action sets in `required_actions`. Otherwise the edge is kept as `latent: true` (shown in the UI, not used for paths) and reported.
- `member_of` stays structural; `iam:AddUserToGroup` produces `modify_permissions` X → group G (X obtains G's policies), and group nodes take part in paths.
- `passrole_compute` X → Y requires: `iam:PassRole` on Y (with `PassedToService` evaluated), Y trusts the service principal, and the compute actions of the rule. Prerequisites that need inventory (e.g., an ECS cluster exists) → `conditional` with `prerequisites_unverified`.

---

## 7. Rule catalog v1

Severity column is the **base** severity; a finding is raised to `critical` when the edge lies on an enumerated path to Tier 0. Findings are per (rule, edge); `path_id` points to the shortest path through that edge, if any.

### 7.1 Path rules (30)

| ID | pathfinding.cloud | Title | Category | Sev. | Edge | Required actions | Prerequisites | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EL-PE-001 | iam-001 | Create new default version of an attached policy | self-escalation | critical | modify_permissions → sink | `iam:CreatePolicyVersion` | customer managed policy attached to X (direct or via group) | stable |
| EL-PE-002 | iam-005 | Put inline policy on own role | self-escalation | critical | → sink | `iam:PutRolePolicy` | X is a role | stable |
| EL-PE-003 | iam-007 | Put inline policy on own user | self-escalation | critical | → sink | `iam:PutUserPolicy` | X is a user | stable |
| EL-PE-004 | iam-008 | Attach managed policy to own user | self-escalation | critical | → sink | `iam:AttachUserPolicy` | X is a user | stable |
| EL-PE-005 | iam-009 | Attach managed policy to own role | self-escalation | critical | → sink | `iam:AttachRolePolicy` | X is a role | stable |
| EL-PE-006 | iam-010 | Attach managed policy to own group | self-escalation | critical | → sink | `iam:AttachGroupPolicy` | X member of the group | stable |
| EL-PE-007 | iam-011 | Put inline policy on own group | self-escalation | critical | → sink | `iam:PutGroupPolicy` | X member of the group | stable |
| EL-PE-008 | iam-013 | Add self to a privileged group | self-escalation | high | modify_permissions → group | `iam:AddUserToGroup` | X is a user | stable |
| EL-PE-009 | iam-002 | Create access key for another user | principal-access | high | credential | `iam:CreateAccessKey` | target has < 2 keys (needs `extras.access_keys`; else conditional) | stable |
| EL-PE-010 | iam-003 | Rotate out and create access key for another user | principal-access | high | credential | `iam:CreateAccessKey`, `iam:DeleteAccessKey` | — | stable |
| EL-PE-011 | iam-004 | Create console password for another user | principal-access | high | credential | `iam:CreateLoginProfile` | target has no login profile (needs extras; else conditional) | stable |
| EL-PE-012 | iam-006 | Change console password of another user | principal-access | high | credential | `iam:UpdateLoginProfile` | target has a login profile; MFA may block (noted) | stable |
| EL-PE-013 | iam-012 | Rewrite a role's trust policy | principal-access | high | modify_trust | `iam:UpdateAssumeRolePolicy` (+ `sts:AssumeRole` per §2.4 once trust names X) | — | stable |
| EL-PE-014 | sts-001 | Assume a more privileged role | principal-access | medium | assume | `sts:AssumeRole` | trust accepts X (§2.4) | stable |
| EL-PE-015 | iam-014 | Attach policy to a role you can assume | principal-access | critical | composite → sink | `iam:AttachRolePolicy`, `sts:AssumeRole` | — | stable |
| EL-PE-016 | iam-016 | New policy version on a role you can assume | principal-access | critical | composite → sink | `iam:CreatePolicyVersion`, `sts:AssumeRole` | policy attached to the role | stable |
| EL-PE-017 | iam-017 | Inline policy on a role you can assume | principal-access | critical | composite → sink | `iam:PutRolePolicy`, `sts:AssumeRole` | — | stable |
| EL-PE-018 | iam-015 | Attach policy to a user and create its key | principal-access | critical | composite → sink | `iam:AttachUserPolicy`, `iam:CreateAccessKey` | key-count as EL-PE-009 | stable |
| EL-PE-019 | iam-018 | Inline policy on a user and create its key | principal-access | critical | composite → sink | `iam:PutUserPolicy`, `iam:CreateAccessKey` | idem | stable |
| EL-PE-020 | iam-019 / iam-020 / iam-021 | Modify permissions and trust of a role | principal-access | critical | composite → sink | (`iam:AttachRolePolicy` \| `iam:CreatePolicyVersion` \| `iam:PutRolePolicy`) + `iam:UpdateAssumeRolePolicy` | — | stable |
| EL-PE-021 | ec2-001 | Pass role to a new EC2 instance | new-passrole | high | passrole_compute | `iam:PassRole`, `ec2:RunInstances` | role trusts `ec2.amazonaws.com` and is in an instance profile (`InstanceProfileList`) | stable |
| EL-PE-022 | lambda-001 | Pass role to a new Lambda and invoke it | new-passrole | high | passrole_compute | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` | role trusts `lambda.amazonaws.com` | stable |
| EL-PE-023 | cloudformation-001 | Pass role to a new CloudFormation stack | new-passrole | high | passrole_compute | `iam:PassRole`, `cloudformation:CreateStack` | role trusts `cloudformation.amazonaws.com` | stable |
| EL-PE-024 | codebuild-001 | Pass role to a new CodeBuild project | new-passrole | high | passrole_compute | `iam:PassRole`, `codebuild:CreateProject`, `codebuild:StartBuild` | role trusts `codebuild.amazonaws.com` | stable |
| EL-PE-025 | glue-003 | Pass role to a new Glue job | new-passrole | high | passrole_compute | `iam:PassRole`, `glue:CreateJob`, `glue:StartJobRun` | role trusts `glue.amazonaws.com` | stable |
| EL-PE-026 | ecs-002 / ecs-004 | Pass role to a new ECS task | new-passrole | high | passrole_compute | `iam:PassRole`, `ecs:RegisterTaskDefinition`, `ecs:RunTask` (+ `ecs:CreateCluster` if no cluster) | role trusts `ecs-tasks.amazonaws.com`; cluster existence unknown → conditional | experimental |
| EL-PE-027 | sagemaker-001 | Pass role to a new SageMaker notebook | new-passrole | high | passrole_compute | `iam:PassRole`, `sagemaker:CreateNotebookInstance` | role trusts `sagemaker.amazonaws.com` | stable |
| EL-PE-028 | lambda-004 | Update code of an existing Lambda and invoke it | existing-passrole | high | update_code | `lambda:UpdateFunctionCode`, `lambda:InvokeFunction` | function with role Y (inventory `lambda`; else conditional) | stable |
| EL-PE-029 | ssm-002 | Run command on an instance with a role | existing-passrole | high | update_code | `ssm:SendCommand` | managed instance with profile of Y (inventory `ec2`; else conditional) | experimental |
| EL-PE-030 | codebuild-002 | Start build of an existing project with buildspec override | existing-passrole | high | update_code | `codebuild:StartBuild` | project with service role Y (inventory `codebuild`; else conditional) | experimental |

(30 rows: 27 stable + 3 experimental, covering 33 pathfinding.cloud IDs because EL-PE-020 and EL-PE-026 group variants.)

Every rule's **detection logic** is the same template: for each candidate pair (X, Y) of the edge kind, call the evaluator for every required action on the resource the action authorizes (Y's ARN, the policy ARN, `*` for create-style actions, per the catalog's `Resources`), and for `iam:PassRole` with `iam:PassedToService` set; the edge status is the weakest of all results (`Allow` < `Conditional`; any deny → no edge). **Remediation** per rule (draft, refined in Phase 6): remove the action from the deciding statement, scope `Resource` to specific ARNs, add `iam:PassedToService`, or attach a permissions boundary that denies the action; each `docs/rules/<ID>.md` will carry a vulnerable and a fixed policy. **References**: AWS doc page of the action, the pathfinding.cloud page, CWE-269 (Improper Privilege Management) for all, CWE-266 for `PassRole` rules.

### 7.2 Trust rules (6)

| ID | Title | Sev. | Logic | Status |
| --- | --- | --- | --- | --- |
| EL-TR-001 | Role trusts any AWS principal | critical | trust `Allow` with `Principal` `*`/`{"AWS":"*"}` and no evaluated condition restricting it (`aws:PrincipalOrgID`, `aws:PrincipalAccount`, `aws:PrincipalArn`) | stable |
| EL-TR-002 | GitHub Actions OIDC trust without `sub` condition | critical | `Federated` = `…:oidc-provider/token.actions.githubusercontent.com` and no condition on `token.actions.githubusercontent.com:sub` | stable |
| EL-TR-003 | GitHub Actions OIDC trust with broad `sub` | high | `sub` pattern is `*`, `repo:*`, `repo:<org>/*` or lacks a ref/environment part | stable |
| EL-TR-004 | Trust to an external account not in the allowlist | medium | account principal not in snapshot nor in `.escalint.yaml` `trusted_accounts` | stable |
| EL-TR-005 | Third-party trust without `sts:ExternalId` | high | account listed as `third_party` in `.escalint.yaml` and no `sts:ExternalId` condition | stable |
| EL-TR-006 | Generic OIDC/SAML trust without audience/subject condition | medium | `Federated` principal (not GitHub) and no condition on `<provider>:aud`/`:sub` (OIDC) or `SAML:aud` (SAML) | experimental |

Plus `EL-PARSE-001` (policy could not be parsed / invalid element such as E21, E31) — `info`, and `EL-PARSE-002` (a reference points to nothing in the snapshot: an attached managed policy or boundary that was not collected, or a group that does not exist) — `info`; the evaluator treats the unknown permissions as `conditional`.

### 7.3 Not covered in v1 (published in `docs/coverage.md`)

pathfinding.cloud lists **92 AWS paths** (8 self-escalation, 14 principal-access, 47 new-passrole, 23 existing-passrole). v1 covers 33. Not covered: the remaining new-passrole/existing-passrole services (apprunner, batch, bedrock-agentcore, braket, cloudformation-002…005, codebuild-003/004, codedeploy, cognito-identity, datapipeline, ec2-002…005, ec2-instance-connect, ecs-001/003/005…009, emr, emr-serverless, gamelift, glue-001/002/004…007, imagebuilder, kinesisanalytics, lambda-002/003/005/006, omics, sagemaker-002…005, scheduler, ssm-001/003, stepfunctions). They are the natural Phase-8 backlog and the "how to add a rule" exercise.

### 7.4 pathfinding.cloud license

The repository is **Apache-2.0** (`LICENSE`, `NOTICE`: "Copyright 2025-Present Datadog, Inc."). Embedding data is allowed with attribution. Proposal: embed only **IDs, names, categories and URLs** (in `internal/rules/pathfinding.json` with the commit SHA), keep our own descriptions, and reproduce the NOTICE in `THIRD_PARTY_NOTICES.md`.

---

## 8. Snapshot format (proposal)

Input accepted by `analyze`/`scan`:

1. **Raw** output of `aws iam get-account-authorization-details` (CLI already decodes documents into JSON objects; the account ID is inferred from ARNs). Wrapped internally into the envelope.
2. **Envelope** (written by `collect`):

```jsonc
{
  "escalint_snapshot": "1",
  "collected_at": "2026-10-23T12:00:00Z",
  "collector": { "name": "escalint", "version": "0.1.0" },
  "partition": "aws",
  "accounts": [{
    "account_id": "111111111111",
    "authorization_details": {            // merged pages of GetAccountAuthorizationDetails, as returned
      "UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []
    },
    "identity_providers": { "oidc": [{ "arn": "…", "url": "…", "client_ids": [] }], "saml": [{ "arn": "…" }] },
    "extras": {                           // optional; absent ⇒ related prerequisites become conditional
      "access_keys": { "<user arn>": [{ "status": "Active" }] },
      "login_profiles": { "<user arn>": true }
    },
    "resources": {                        // optional inventory (--resources)
      "lambda": [{ "arn": "…", "role": "…" }],
      "ec2": [{ "arn": "…", "instance_profile": "…", "ssm_managed": true }],
      "codebuild": [{ "arn": "…", "service_role": "…" }]
    }
  }],
  "organization": {                       // optional (--org)
    "id": "o-…", "management_account_id": "…",
    "tree": [{ "id": "r-…", "type": "ROOT", "parent": null }, { "id": "ou-…", "type": "OU", "parent": "r-…" },
             { "id": "111111111111", "type": "ACCOUNT", "parent": "ou-…" }],
    "policies": [{ "id": "p-…", "type": "SERVICE_CONTROL_POLICY|RESOURCE_CONTROL_POLICY",
                   "name": "…", "document": {}, "targets": ["r-…", "ou-…", "111111111111"] }]
  }
}
```

Policy documents are accepted as **JSON object**, **JSON string** or **URL-encoded string** (RFC 3986, as documented in [authz-details]; the Go SDK returns them encoded).

---

## 9. `analysis.json` skeleton (proposal, ADR 0003)

As in `project.md` §3.3, with these changes:

- `edges[].kind` adds `admin`; `edges[]` adds `latent` (bool), `prerequisites_unverified` (string[]), `actor` only for composites (the principal that performs the modification).
- `nodes[]` adds `tier_conditional` (bool) and `service_linked` (bool).
- `findings[]` adds `edge_id`; `suppressed` becomes `{ "reason", "expires", "source" } | null`; top-level `suppressions[]`.
- `evaluations` is a map `eval_id → { decision, steps: [{ step, policy_ref, statement_index, sid, effect, matched }] }`, referenced from `edges[].evidence[].eval_id`.
- `diff` (optional): `{ "base": {...}, "added": { "edges": [], "paths": [], "findings": [] }, "removed": {...} }`.
- IDs: `n_`/`e_`/`p_`/`f_` + first 16 hex of SHA-256 over a canonical key (node ARN; edge `from|to|kind|rule`), computed **before** redaction (ADR 0010).

---

## 10. `collect` API calls and minimal policy

Default (all `List*`/`Get*`):

| Call | Purpose |
| --- | --- |
| `sts:GetCallerIdentity` | account ID / partition (no permission required) |
| `iam:GetAccountAuthorizationDetails` | users, groups, roles, policies |
| `iam:ListOpenIDConnectProviders`, `iam:GetOpenIDConnectProvider` | OIDC providers (EL-TR-002/003/006) |
| `iam:ListSAMLProviders` | SAML providers |
| `iam:ListAccessKeys` (per user) | key count prerequisite (EL-PE-009/018/019) |
| `iam:GetLoginProfile` (per user) | console password prerequisite (EL-PE-011/012) |

Behind opt-in flags (off by default), with justification:

| Flag | Calls | Justification |
| --- | --- | --- |
| `--org` | `organizations:DescribeOrganization`, `ListRoots`, `ListOrganizationalUnitsForParent`, `ListAccountsForParent`, `ListPolicies` (SCP, RCP), `DescribePolicy`, `ListTargetsForPolicy` | `Describe*` are read-only; must run in the management or delegated-admin account; without it SCP/RCP are unknown |
| `--resources lambda,ec2,codebuild` | `lambda:ListFunctions`, `ec2:DescribeInstances`, `ec2:DescribeIamInstanceProfileAssociations`, `ssm:DescribeInstanceInformation`, `codebuild:ListProjects`, `codebuild:BatchGetProjects` | `Describe*`/`BatchGet*` are read-only; needed for `update_code` edges |
| `--assume-roles <file>` | `sts:AssumeRole` | **needs your approval**: it is not a write, but it changes scope (multi-account). Proposal: allow, document, off by default |

Not used: `GenerateCredentialReport`, `GenerateServiceLastAccessedDetails` (they create server-side jobs; `RoleLastUsed` from authorization details is enough for `stale` on roles). Users have no last-used in `UserDetail`; `stale` applies to roles only in v1.

---

## 11. GitHub Actions runners

Verified: standard GitHub-hosted runners are "free and unlimited on public repositories", including **`ubuntu-latest`, `windows-latest` and `macos-latest`** (and `ubuntu-24.04-arm`); **larger runners are always charged** ([gh-billing], [gh-runners]). Proposal: `go-test-os` on `windows-latest` and `macos-latest`; never larger runners.

---

## 12. Tooling versions verified today

- Go: latest stable **go1.27.3** (go.dev/dl). Local machine has go1.22.2 → `go.mod` will declare `go 1.27` + `toolchain go1.27.3` and the toolchain will be downloaded automatically.
- Node: local v25.8.1 (not LTS); `.nvmrc` will pin the current LTS (to confirm in Phase 1).
- Service reference: `https://servicereference.us-east-1.amazonaws.com/` (index with `service`, `url`, `modified`), per-service files with `Name`, `ServiceName`, `Actions[].Name`, `Actions[].Annotations.Properties.{IsList,IsPermissionManagement,IsTaggingOnly,IsWrite,IsDataPlane}`, `Actions[].Resources`, `ActionConditionKeys`, `Resources[].ARNFormats`, `ConditionKeys`, `Version` (`v1.5` today).

[denyallow]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
[cross-account]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html
[scps]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
[scps_evaluation]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
[rcps]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
[principal]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
[notprincipal]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
[notaction]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html
[resource]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
[condition-operators]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
[set-operators]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
[passrole]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html
[AssumeRole]: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
[authz-details]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html
[catalog]: https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html
[gh-billing]: https://docs.github.com/en/billing/concepts/product-billing/github-actions
[gh-runners]: https://docs.github.com/en/actions/reference/runners/github-hosted-runners

---

## 13. MITRE ATT&CK mapping (Phase 1E, ADR 0021)

**Source:** `mitre-attack/attack-stix-data`, bundle `enterprise-attack/enterprise-attack-20.0.json`
(Enterprise ATT&CK **v20.0**, released 2026-10-13; SHA-256
`81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`).

**Verification performed (2026-10-23)** for every technique used below:
present in the v20.0 bundle, not `revoked`, not `x_mitre_deprecated`, `IaaS` in
`x_mitre_platforms`, and the page `https://attack.mitre.org/techniques/<ID>/`
returns 200 with no deprecation notice. Names and tactics come from the bundle,
never typed by hand (v20 renamed tactics, e.g. *Stealth*, *Defense Impairment*).

**Terms of use** ([terms](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/),
`LICENSE.txt` of the STIX repository): royalty-free license for research,
development and commercial use; every copy must reproduce MITRE's copyright
designation and the license. Required notice:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

"MITRE ATT&CK" and "ATT&CK" are registered trademarks of The MITRE Corporation.
The notice and license go into `NOTICE`, `THIRD_PARTY_NOTICES.md` and the README
when the extracted data is embedded (Phase 6).

### 13.1 Techniques used

| ID | Name (v20.0) | Tactics | Why it applies (official text) |
| --- | --- | --- | --- |
| T1098.003 | Additional Cloud Roles | Persistence, Privilege Escalation | "in AWS environments, an adversary … may be able to use the `CreatePolicyVersion` API … or the `AttachUserPolicy` API"; also "add roles to adversary-controlled accounts outside the victim tenant" |
| T1098.001 | Additional Cloud Credentials | Persistence, Privilege Escalation | "use the `CreateAccessKey` API … `CreateLoginProfile` API … If the target account has different permissions … escalate their privileges" |
| T1548.005 | Temporary Elevated Cloud Access | Privilege Escalation | "pass roles onto resources and services … In AWS, users with the `PassRole` permission can allow a service they create to assume a given role"; "configuring the resource to perform certain actions with the permissions it has been granted" |
| T1078.004 | Cloud Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | use of valid cloud identities (assumed roles, created keys) |
| T1648 | Serverless Execution | Execution | "use the `IAM:PassRole` permission in AWS … to add Additional Cloud Roles to a serverless cloud function" |
| T1651 | Cloud Administration Command | Execution | "Resources such as AWS Systems Manager … allow users to remotely run scripts in virtual machines" |
| T1199 | Trusted Relationship | Initial Access | third-party / external providers granted access to cloud environments |

Rejected candidates: **T1484.002 Trust Modification** (no IaaS platform in v20.0),
**T1098.007** (Windows/macOS/Linux only), **T1555.006** (no v1 rule extracts
secrets), **T1606.002 SAML Tokens** (forging tokens is not what EL-TR-006 detects).

### 13.2 Rule → technique

| Rule | Techniques |
| --- | --- |
| EL-PE-001…007 (self policy changes) | T1098.003 |
| EL-PE-008 (AddUserToGroup) | T1098.003 |
| EL-PE-009…012 (keys, login profile) | T1098.001, T1078.004 |
| EL-PE-013 (UpdateAssumeRolePolicy) | T1098.003 |
| EL-PE-014 (AssumeRole) | T1548.005, T1078.004 |
| EL-PE-015…017 (modify + assume) | T1098.003, T1548.005 |
| EL-PE-018, 019 (modify + create key) | T1098.003, T1098.001 |
| EL-PE-020 (modify + rewrite trust) | T1098.003 |
| EL-PE-021, 023…027 (new PassRole) | T1548.005 |
| EL-PE-022 (PassRole + Lambda) | T1548.005, T1648 |
| EL-PE-028 (Lambda update code) | T1648, T1548.005 |
| EL-PE-029 (SSM SendCommand) | T1651, T1548.005 |
| EL-PE-030 (CodeBuild StartBuild) | T1548.005 |
| EL-TR-001 (trust `*`) | T1078.004 |
| EL-TR-002, 003 (GitHub OIDC) | T1199, T1078.004 |
| EL-TR-004, 005 (external / third party) | T1199 |
| EL-TR-006 (generic OIDC/SAML) | T1199, T1078.004 |
| EL-PARSE-001 | unmapped: parser diagnostic, not adversary behavior |

---

## 14. CloudTrail detection (Phase 1E, ADR 0022)

### 14.1 Verified nuances

| # | Nuance | Source |
| --- | --- | --- |
| C1 | `iam:PassRole` is a permission, not an API call: no CloudTrail event; look for the outer call (`RunInstances`, `CreateFunction20150331`…) with the role in `requestParameters` | [passrole] |
| C2 | Lambda management `eventName`s carry version suffixes: `CreateFunction20150331`, `UpdateFunctionCode20150331v2`, `AddPermission20150331v2`, `CreateEventSourceMapping20150331`; the service reference lists them without suffix, so generated names need overrides | [lambda-ct] |
| C3 | `CreateFunction` omits `Environment` and `ZipFile`; `UpdateFunctionCode` omits `ZipFile`: the malicious code itself is never in CloudTrail | [lambda-ct] |
| C4 | Lambda `Invoke` is a **data event**; trails and event data stores do not log data events by default and Event history never shows them | [lambda-ct], [ct-concepts] |
| C5 | IAM and STS-global-endpoint events are recorded in **us-east-1**; STS regional endpoints log in their own Region; Event history shows events where they occurred | [ct-concepts], [iam-ct] |
| C6 | Cross-account `AssumeRole` is logged in **both** accounts: caller's account (`userIdentity` = the caller) and role owner's account (`userIdentity.type = AWSAccount`), linked by `sharedEventID` | [iam-ct] |
| C7 | **Denied** cross-account `AssumeRole` is **not** logged in the target account | [iam-ct] |
| C8 | `AssumeRole`, `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity` are `readOnly: true`; a trail that keeps only write management events misses every role assumption | [iam-ct] |
| C9 | `AssumeRoleWithWebIdentity` / `WithSAML` are logged only in the role's account with `userIdentity.type` `WebIdentityUser` / `SAMLUser`; `responseElements.subjectFromWebIdentityToken` carries the OIDC `sub` (e.g. the GitHub repo/ref) | [iam-ct] |
| C10 | Calls made later with the obtained role show only the role session (`AssumedRole`), not the original user; `sts:SourceIdentity` is the only way to keep attribution | [iam-ct] |
| C11 | `ssm:SendCommand` is a management event; what the command does on the instance is not in CloudTrail; SSM data events (`RequestManagedInstanceRoleToken`, control channel) are off by default | [ssm-ct] |
| C12 | CloudFormation logs only parameter **keys**, not values | [cfn-ct] |
| C13 | Glue omits sensitive fields (e.g. `ConnectionProperties`) and logs `null` responses for many Get APIs | [glue-ct] |
| C14 | EC2, ECS, SageMaker, CodeBuild control-plane calls are management events | [ec2-ct], [ecs-ct], [sm-ct], [cb-ct] |
| C15 | Activity **inside** compute (code that runs, credential reads from instance metadata or the Lambda environment) generates no event; only subsequent API calls made with the role appear | inferred from C3, C10, C11 — `experimental` |

### 14.2 Detection hints per edge kind

| Edge kind | Events (eventSource / eventName) | Kind | Blind spots |
| --- | --- | --- | --- |
| assume | `sts` / `AssumeRole` | management, read-only | C7, C8, C10 |
| trust (OIDC) | `sts` / `AssumeRoleWithWebIdentity` | management, read-only | C8; only in role account |
| trust (SAML) | `sts` / `AssumeRoleWithSAML` | management, read-only | C8 |
| credential | `iam` / `CreateAccessKey`, `DeleteAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`; then `signin` / `ConsoleLogin` | management | key use later appears as the victim user (C10) |
| modify_permissions | `iam` / `CreatePolicyVersion`, `Put{User,Role,Group}Policy`, `Attach{User,Role,Group}Policy`, `AddUserToGroup` | management | — |
| modify_trust | `iam` / `UpdateAssumeRolePolicy` | management | — |
| passrole_compute | the compute call: `ec2` / `RunInstances`, `lambda` / `CreateFunction20150331` (+ `Invoke`), `cloudformation` / `CreateStack`, `codebuild` / `CreateProject` + `StartBuild`, `glue` / `CreateJob` + `StartJobRun`, `ecs` / `RegisterTaskDefinition` + `RunTask`, `sagemaker` / `CreateNotebookInstance` | management (+ data for Invoke) | C1, C3, C4, C12, C15 |
| update_code | `lambda` / `UpdateFunctionCode20150331v2` (+ `Invoke`), `ssm` / `SendCommand`, `codebuild` / `StartBuild` | management (+ data) | C3, C4, C11, C15 |
| member_of, admin | none (structural) | — | not exploitation steps |

Status: **verified** = event source, name and category confirmed in the service's
CloudTrail documentation (all rows above). **experimental** = key-field paths
not shown in an official sample event (e.g. `requestParameters.iamInstanceProfile`
for `RunInstances`, `requestParameters.serviceRole` for `CreateProject`) and C15.

[lambda-ct]: https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
[ct-concepts]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
[iam-ct]: https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
[ssm-ct]: https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html
[cfn-ct]: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-api-logging-cloudtrail.html
[glue-ct]: https://docs.aws.amazon.com/glue/latest/dg/monitor-cloudtrail.html
[ec2-ct]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitor-with-cloudtrail.html
[ecs-ct]: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/logging-using-cloudtrail.html
[sm-ct]: https://docs.aws.amazon.com/sagemaker/latest/dg/logging-using-cloudtrail.html
[cb-ct]: https://docs.aws.amazon.com/codebuild/latest/userguide/cloudtrail.html
