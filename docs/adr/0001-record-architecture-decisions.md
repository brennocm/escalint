# 0001 — Record architecture decisions

Status: Accepted

## Context

escalint is a public portfolio project whose code and design choices are read
by reviewers. Decisions about evaluation semantics, graph modeling, rendering
and security need to be explainable long after they were made.

## Decision

We record every non-obvious decision as an Architecture Decision Record in
`docs/adr/NNNN-title.md` with the sections Context, Decision, Alternatives
considered and Consequences. Records are immutable once accepted; a changed
decision gets a new ADR that supersedes the old one.

## Alternatives considered

- *Decisions only in commit messages or PR descriptions:* hard to find and to
  read as a whole.
- *A single design document:* grows stale and mixes current and past reasoning.

## Consequences

- Reviewers can trace why the code looks the way it does.
- Each ADR costs a few minutes of writing; the list of expected ADRs lives in
  the project specification.
