import type { Node } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';
import { isPrincipal } from '../../data/indexes';

// Exposure matrix: principals × services, each cell the strongest class a
// principal can use there (directly or through principals it can reach).
// Rows are seriated so similar profiles sit together: identical profiles
// are grouped first, then groups are chained greedily by nearest neighbor
// under Jaccard distance over (service, class) pairs, starting from the
// broadest profile. O(g²) in the number g of distinct profiles.

export const classes = ['list', 'read', 'write', 'permission_management'] as const;
export type CapClass = (typeof classes)[number];

/** Cell value: index in `classes`, or -1 when the principal has nothing. */
export type Cell = -1 | 0 | 1 | 2 | 3;

export interface Matrix {
  readonly rows: readonly Node[];
  readonly services: readonly string[];
  /** Row-major cells. */
  readonly cells: Int8Array;
  readonly rowTotals: readonly number[];
  readonly colTotals: readonly number[];
}

function profile(n: Node): Map<string, Cell> {
  const m = new Map<string, Cell>();
  const caps = n.blast?.capabilities;
  if (!caps) return m;
  classes.forEach((c, i) => {
    for (const svc of caps[c]) m.set(svc, i as Cell);
  });
  return m;
}

export function jaccard(a: ReadonlySet<string>, b: ReadonlySet<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return 1 - inter / (a.size + b.size - inter);
}

/** Orders keys (profiles) by greedy nearest-neighbor chaining. */
export function seriate(
  keys: readonly string[],
  sets: ReadonlyMap<string, ReadonlySet<string>>,
): string[] {
  if (keys.length <= 2) return [...keys];
  const left = new Set(keys);
  const size = (k: string): number => sets.get(k)?.size ?? 0;
  let current = [...keys].sort((a, b) => size(b) - size(a) || (a < b ? -1 : 1))[0] ?? '';
  const out = [current];
  left.delete(current);
  while (left.size) {
    let best = '';
    let bestD = Infinity;
    const cur = sets.get(current) ?? new Set<string>();
    for (const k of left) {
      const d = jaccard(cur, sets.get(k) ?? new Set<string>());
      if (d < bestD || (d === bestD && k < best)) {
        best = k;
        bestD = d;
      }
    }
    out.push(best);
    left.delete(best);
    current = best;
  }
  return out;
}

export function buildMatrix(ix: Indexes, filter: (n: Node) => boolean = () => true): Matrix {
  const principals = ix.analysis.nodes.filter((n) => isPrincipal(n) && filter(n));
  const profiles = new Map(principals.map((n) => [n.id, profile(n)]));
  const freq = new Map<string, number>();
  for (const p of profiles.values())
    for (const svc of p.keys()) freq.set(svc, (freq.get(svc) ?? 0) + 1);
  const services = [...freq.keys()].sort(
    (a, b) => (freq.get(b) ?? 0) - (freq.get(a) ?? 0) || (a < b ? -1 : 1),
  );
  // Group identical profiles.
  const groups = new Map<string, Node[]>();
  for (const n of principals) {
    const p = profiles.get(n.id) ?? new Map<string, Cell>();
    const key = [...p.entries()]
      .sort()
      .map(([s, c]) => `${s}=${String(c)}`)
      .join(',');
    const group = groups.get(key);
    if (group) group.push(n);
    else groups.set(key, [n]);
  }
  const sets = new Map([...groups.keys()].map((k) => [k, new Set(k === '' ? [] : k.split(','))]));
  const order = seriate([...groups.keys()], sets);
  const rows = order.flatMap((k) => (groups.get(k) ?? []).sort((a, b) => (a.id < b.id ? -1 : 1)));
  const col = new Map(services.map((s, i) => [s, i]));
  const cells = new Int8Array(rows.length * services.length).fill(-1);
  const rowTotals = rows.map(() => 0);
  const colTotals = services.map(() => 0);
  rows.forEach((n, r) => {
    for (const [svc, c] of profiles.get(n.id) ?? []) {
      const j = col.get(svc);
      if (j === undefined) continue;
      cells[r * services.length + j] = c;
      rowTotals[r] = (rowTotals[r] ?? 0) + 1;
      colTotals[j] = (colTotals[j] ?? 0) + 1;
    }
  });
  return { rows, services, cells, rowTotals, colTotals };
}

export function cellAt(m: Matrix, row: number, col: number): Cell {
  return (m.cells[row * m.services.length + col] ?? -1) as Cell;
}
