import type { Edge } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';
import type { Direction } from '../../state/route';

// Radial layout for Reach: the center principal, then one ring per hop.
// Angular order within a ring comes from the barycenter heuristic: each
// node sits near the mean angle of its neighbors in the previous ring,
// refined by alternating outward and inward sweeps. This is the classic
// Sugiyama crossing-reduction step, applied to concentric layers.

export interface RingNode {
  readonly id: string;
  readonly ring: number;
  /** Angle in radians, 0 at 12 o'clock, clockwise. */
  readonly angle: number;
  readonly x: number;
  readonly y: number;
}

export interface RingEdge {
  readonly id: string;
  readonly from: string; // inner end
  readonly to: string; // outer end
}

export interface ReachLayout {
  readonly nodes: readonly RingNode[];
  readonly edges: readonly RingEdge[];
  readonly rings: readonly (readonly string[])[];
  /** Nodes left out because a ring was full. */
  readonly hidden: number;
  readonly radius: number;
}

export const ringGap = 110;

function usable(e: Edge): boolean {
  return e.kind !== 'member_of' && !e.latent;
}

/** Breadth-first rings around center; each ring keeps at most perRing
 * nodes (by ID) to stay readable. */
export function rings(
  ix: Indexes,
  center: string,
  dir: Direction,
  maxDepth: number,
  perRing: number,
): { rings: string[][]; edges: RingEdge[]; hidden: number } {
  const seen = new Map<string, number>([[center, 0]]);
  const out: string[][] = [[center]];
  const edges: RingEdge[] = [];
  let hidden = 0;
  for (let d = 1; d <= maxDepth; d++) {
    const next = new Set<string>();
    const prev = out[d - 1] ?? [];
    for (const id of prev) {
      const list = (dir === 'out' ? ix.out.get(id) : ix.in.get(id)) ?? [];
      for (const e of list) {
        if (!usable(e)) continue;
        const other = dir === 'out' ? e.to : e.from;
        if (!seen.has(other)) next.add(other);
      }
    }
    if (next.size === 0) break;
    const sorted = [...next].sort();
    const kept = sorted.slice(0, perRing);
    hidden += sorted.length - kept.length;
    for (const id of kept) seen.set(id, d);
    out.push(kept);
  }
  // Edges between consecutive rings (inner → outer in reading order).
  for (let d = 1; d < out.length; d++) {
    const ring = new Set(out[d]);
    for (const id of out[d - 1] ?? []) {
      for (const e of (dir === 'out' ? ix.out.get(id) : ix.in.get(id)) ?? []) {
        const other = dir === 'out' ? e.to : e.from;
        if (usable(e) && ring.has(other)) edges.push({ id: e.id, from: id, to: other });
      }
    }
  }
  return { rings: out, edges, hidden };
}

/** Number of crossing pairs between two consecutive rings, given angular
 * positions (as an order index). Two edges cross when their ends are in
 * opposite order on the two rings. */
export function crossings(edges: readonly RingEdge[], pos: ReadonlyMap<string, number>): number {
  const list = edges.map((e) => [pos.get(e.from) ?? 0, pos.get(e.to) ?? 0] as const);
  let n = 0;
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      const a = list[i];
      const b = list[j];
      if (a && b && (a[0] - b[0]) * (a[1] - b[1]) < 0) n++;
    }
  }
  return n;
}

function orderPositions(rs: readonly (readonly string[])[]): Map<string, number> {
  const pos = new Map<string, number>();
  for (const ring of rs)
    ring.forEach((id, i) => pos.set(id, ring.length > 1 ? i / ring.length : 0));
  return pos;
}

/** Total crossings over all consecutive ring pairs. */
export function totalCrossings(
  rs: readonly (readonly string[])[],
  edges: readonly RingEdge[],
): number {
  // Counted per pair of consecutive rings: edges of different pairs cannot cross.
  const ringOf = new Map<string, number>();
  rs.forEach((r, d) => {
    for (const id of r) ringOf.set(id, d);
  });
  const pos = orderPositions(rs);
  const byRing = new Map<number, RingEdge[]>();
  for (const e of edges) {
    const d = ringOf.get(e.from) ?? 0;
    const ring = byRing.get(d);
    if (ring) ring.push(e);
    else byRing.set(d, [e]);
  }
  let n = 0;
  for (const list of byRing.values()) n += crossings(list, pos);
  return n;
}

/** Barycentric reordering: sweeps outward then inward, `sweeps` times. */
export function barycentric(
  rs: readonly (readonly string[])[],
  edges: readonly RingEdge[],
  sweeps = 4,
): string[][] {
  const order = rs.map((r) => [...r]);
  const neighbors = (id: string, inward: boolean): string[] =>
    edges
      .filter((e) => (inward ? e.to === id : e.from === id))
      .map((e) => (inward ? e.from : e.to));
  const reorder = (d: number, inward: boolean): void => {
    const ring = order[d];
    if (!ring || ring.length < 2) return;
    const pos = orderPositions(order);
    const bary = new Map<string, number>();
    for (const id of ring) {
      const ns = neighbors(id, inward)
        .map((n) => pos.get(n))
        .filter((p): p is number => p !== undefined);
      bary.set(id, ns.length ? ns.reduce((s, p) => s + p, 0) / ns.length : (pos.get(id) ?? 0));
    }
    ring.sort((a, b) => (bary.get(a) ?? 0) - (bary.get(b) ?? 0) || (a < b ? -1 : 1));
  };
  let best = order.map((r) => [...r]);
  let bestCount = totalCrossings(order, edges);
  for (let s = 0; s < sweeps; s++) {
    for (let d = 1; d < order.length; d++) reorder(d, true);
    for (let d = order.length - 2; d >= 1; d--) reorder(d, false);
    const c = totalCrossings(order, edges);
    if (c < bestCount) {
      bestCount = c;
      best = order.map((r) => [...r]);
    }
  }
  return best;
}

export function reachLayout(
  ix: Indexes,
  center: string,
  dir: Direction,
  maxDepth = 4,
  perRing = 60,
): ReachLayout {
  const r = rings(ix, center, dir, maxDepth, perRing);
  const ordered = barycentric(r.rings, r.edges);
  const nodes: RingNode[] = [];
  ordered.forEach((ring, d) => {
    ring.forEach((id, i) => {
      const angle = d === 0 ? 0 : (2 * Math.PI * i) / ring.length;
      const radius = d * ringGap;
      nodes.push({
        id,
        ring: d,
        angle,
        x: Math.round(radius * Math.sin(angle) * 100) / 100,
        y: Math.round(-radius * Math.cos(angle) * 100) / 100,
      });
    });
  });
  return {
    nodes,
    edges: r.edges,
    rings: ordered,
    hidden: r.hidden,
    radius: (ordered.length - 1) * ringGap,
  };
}
