# 0009 — Fix plan: greedy hitting set and its limits

Status: Accepted

## Context

Defenders want the smallest set of changes that removes every escalation
path found. Choosing the minimum set of edges that intersects every path is
the minimum hitting set problem, which is NP-hard.

## Decision

- Use the greedy approximation: repeatedly pick the edge that cuts the most
  remaining enumerated paths (ties by edge ID) until every path is cut. Its
  result is within a factor of ln(n) + 1 of the optimum.
- Edges that a policy change cannot remove (`admin`: the principal *is* an
  administrator) are only chosen when a path has no other edge.
- Each step lists the paths it cuts; the engine turns the edge evidence into
  a concrete change ("remove iam:PassRole from statement Sid=X of policy P").
- A property test checks that removing the plan's edges leaves no enumerated
  path intact.

## Limitations

- The plan covers enumerated paths (k per source, depth limit); after
  applying it, a re-scan may find paths that were not in the top k.
- It optimizes the number of edges, not the effort or blast of each change.
- Removing an edge may require editing a policy shared by other principals;
  the change text names the policy so reviewers can judge that.

## Alternatives considered

- *Exact solver (ILP):* exact but slow and heavy for a CLI; greedy is
  deterministic, explainable and good enough.
- *Cut only choke points:* misses paths that share no edge.
