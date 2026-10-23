# 0005 — Unevaluated conditions produce Conditional, never silence

Status: Accepted

## Context

Most condition keys exist only at request time (MFA, source IP, region,
time, session tags). A static analyzer cannot know them. Treating unknown
conditions as false would hide real escalation paths; treating them as true
would claim certainty we do not have.

## Decision

- Only statically known keys are evaluated: `aws:PrincipalArn`,
  `aws:PrincipalAccount`, `aws:PrincipalOrgID` (when organization data
  exists), `aws:PrincipalIsAWSService`, `iam:PassedToService`, `aws:username`
  and `aws:userid` (research §2.7).
- Any other key, and any operator outside String*, Arn*, Bool and Null,
  makes the statement **conditional**.
- A conditional `Allow` makes the decision `Conditional` (an edge with status
  `conditional`). A conditional `Deny` over an otherwise allowed request also
  gives `Conditional`, never `Deny`.
- A policy whose content is unknown (not collected, not parsable) counts as a
  possible allow and a possible deny (`escalint:unknown-policy`).
- Every conditional decision lists the keys that would settle it
  (`Result.Unevaluated`); the UI and reports show them.
- For principals known to be outside the analyzed organization,
  `aws:PrincipalOrgID` compared only with our organization ID is decided
  (false for equality), so the common "trust * within our org" pattern does
  not turn into noise.

## Consequences

- Some reported paths will be blocked in practice by MFA or IP conditions;
  they are labeled `conditional` with the keys to check.
- No path disappears because escalint could not evaluate something.
