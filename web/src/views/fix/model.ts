import type { Path } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';

/** Paths that survive when the edges of the applied steps are removed
 * (the client-side preview of the fix plan). */
export function remainingPaths(ix: Indexes, applied: ReadonlySet<number>): Path[] {
  const removed = new Set(
    ix.analysis.fix_plan.filter((s) => applied.has(s.order)).map((s) => s.edge_id),
  );
  return ix.analysis.paths.filter((p) => !p.edges.some((e) => removed.has(e)));
}

/** Steps 1..n, the default preview selection. */
export function firstSteps(n: number): Set<number> {
  return new Set(Array.from({ length: n }, (_, i) => i + 1));
}
