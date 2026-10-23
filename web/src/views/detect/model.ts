import type { Edge, Path } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';
import { severityRank } from '../../data/indexes';

export interface StepRow {
  readonly path: Path;
  readonly step: number;
  readonly edge: Edge;
}

/** Every step of the critical and high paths, worst paths first: what a
 * detection engineer needs to cover. */
export function detectionRows(ix: Indexes, limit = 400): StepRow[] {
  const paths = [...ix.analysis.paths].sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      a.length - b.length ||
      (a.id < b.id ? -1 : 1),
  );
  const rows: StepRow[] = [];
  for (const p of paths) {
    p.edges.forEach((id, i) => {
      const edge = ix.edges.get(id);
      if (edge && rows.length < limit) rows.push({ path: p, step: i + 1, edge });
    });
  }
  return rows;
}

export interface EventCount {
  readonly source: string;
  readonly name: string;
  readonly kind: string;
  readonly steps: number;
}

/** CloudTrail events to alert on, by how many path steps produce them. */
export function eventCounts(rows: readonly StepRow[]): EventCount[] {
  const m = new Map<string, EventCount>();
  const seen = new Set<string>();
  for (const r of rows) {
    for (const e of r.edge.detection.events) {
      const key = `${e.source}/${e.name}`;
      const once = `${key}|${r.edge.id}`;
      if (seen.has(once)) continue;
      seen.add(once);
      const cur = m.get(key);
      m.set(key, { source: e.source, name: e.name, kind: e.kind, steps: (cur?.steps ?? 0) + 1 });
    }
  }
  return [...m.values()].sort((a, b) => b.steps - a.steps || (a.name < b.name ? -1 : 1));
}
