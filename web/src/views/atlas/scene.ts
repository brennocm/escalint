import type { Edge, Node } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';
import type { Theme } from '../../design/tokens';
import { conditionalDash, edgeDash, nodeRadius, type Tier } from '../../design/tokens';
import type { Filters } from '../../state/route';
import { dashArray, EdgeFlag, NodeFlag, type EdgeAttrs, type NodeAttrs } from './renderer';
import { kindCodes } from './sdf';

// Scene: what the Atlas draws, as flat arrays indexed like `nodes`.

export interface Scene {
  readonly nodes: readonly Node[];
  readonly index: ReadonlyMap<string, number>;
  readonly edges: readonly Edge[];
  readonly edgeFrom: Uint32Array;
  readonly edgeTo: Uint32Array;
  /** Outgoing usable edges per node index (for 1-hop focus and paths). */
  readonly out: readonly (readonly number[])[];
  readonly inn: readonly (readonly number[])[];
}

export function buildScene(ix: Indexes): Scene {
  const nodes = [...ix.analysis.nodes].sort((a, b) => (a.id < b.id ? -1 : 1));
  const index = new Map(nodes.map((n, i) => [n.id, i]));
  const edges = ix.analysis.edges.filter((e) => index.has(e.from) && index.has(e.to));
  const edgeFrom = new Uint32Array(edges.length);
  const edgeTo = new Uint32Array(edges.length);
  const out: number[][] = nodes.map(() => []);
  const inn: number[][] = nodes.map(() => []);
  edges.forEach((e, k) => {
    const a = index.get(e.from) ?? 0;
    const b = index.get(e.to) ?? 0;
    edgeFrom[k] = a;
    edgeTo[k] = b;
    if (e.kind !== 'member_of' && !e.latent) {
      out[a]?.push(k);
      inn[b]?.push(k);
    }
  });
  return { nodes, index, edges, edgeFrom, edgeTo, out, inn };
}

export function visible(n: Node, f: Filters): boolean {
  if (f.tiers.length && !f.tiers.includes(n.tier)) return false;
  if (f.kinds.length && !f.kinds.includes(n.kind)) return false;
  if (f.accounts.length && !f.accounts.includes(n.account)) return false;
  if (f.stale && !n.flags.includes('stale')) return false;
  return true;
}

export interface Focus {
  readonly hover: number; // node index or -1
  readonly selected: number;
  /** Highlighted path (Shift+click or critical overlay): edge indices. */
  readonly pathEdges: ReadonlySet<number>;
}

/** Nodes within one hop of a node (both directions), itself included. */
export function neighborhood(s: Scene, i: number): Set<number> {
  const set = new Set([i]);
  for (const k of s.out[i] ?? []) set.add(s.edgeTo[k] ?? 0);
  for (const k of s.inn[i] ?? []) set.add(s.edgeFrom[k] ?? 0);
  return set;
}

/** Shortest directed path between two node indices (BFS), as edge
 * indices; tries a → b, then b → a. Empty when none. */
export function shortestPath(s: Scene, a: number, b: number): number[] {
  const run = (from: number, to: number): number[] => {
    const prev = new Map<number, number>([[from, -1]]);
    const queue = [from];
    while (queue.length) {
      const v = queue.shift() ?? 0;
      if (v === to) break;
      for (const k of s.out[v] ?? []) {
        const w = s.edgeTo[k] ?? 0;
        if (!prev.has(w)) {
          prev.set(w, k);
          queue.push(w);
        }
      }
    }
    if (!prev.has(to) || from === to) return [];
    const path: number[] = [];
    for (let v = to; v !== from;) {
      const k = prev.get(v) ?? -1;
      path.unshift(k);
      v = s.edgeFrom[k] ?? from;
    }
    return path;
  };
  const forward = run(a, b);
  return forward.length ? forward : run(b, a);
}

export function nodeAttrs(
  s: Scene,
  ix: Indexes,
  theme: Theme,
  x: Float32Array,
  y: Float32Array,
  f: Filters,
  focus: Focus,
): NodeAttrs {
  const n = s.nodes.length;
  const radius = new Float32Array(n);
  const kind = new Float32Array(n);
  const flags = new Uint8Array(n);
  const ring: string[] = [];
  const focusSet =
    focus.hover >= 0
      ? neighborhood(s, focus.hover)
      : focus.selected >= 0
        ? neighborhood(s, focus.selected)
        : null;
  const pathNodes = new Set<number>();
  for (const k of focus.pathEdges) {
    pathNodes.add(s.edgeFrom[k] ?? 0);
    pathNodes.add(s.edgeTo[k] ?? 0);
  }
  s.nodes.forEach((node, i) => {
    radius[i] =
      node.kind === 'tier0_sink'
        ? 16
        : nodeRadius(node.blast?.reachable_principals ?? 0, ix.maxReach);
    kind[i] = kindCodes[node.kind];
    ring.push(theme.tier[node.tier as Tier]);
    let fl = 0;
    if (node.flags.includes('stale')) fl |= NodeFlag.stale;
    if (node.tier_conditional) fl |= NodeFlag.conditional;
    if (node.tier === 0) fl |= NodeFlag.tier0;
    if (i === focus.selected) fl |= NodeFlag.selected;
    if (i === focus.hover) fl |= NodeFlag.hover;
    if (!visible(node, f)) fl |= NodeFlag.hidden;
    const inFocus = focus.pathEdges.size ? pathNodes.has(i) : focusSet ? focusSet.has(i) : true;
    if (!inFocus) fl |= NodeFlag.dimmed;
    flags[i] = fl;
  });
  return { x, y, radius, kind, ring, flags };
}

export function edgeAttrs(
  s: Scene,
  ix: Indexes,
  theme: Theme,
  nodes: NodeAttrs,
  focus: Focus,
): EdgeAttrs {
  const m = s.edges.length;
  const width = new Float32Array(m);
  const dash = new Float32Array(m * 4);
  const flags = new Uint8Array(m);
  const color: string[] = [];
  const focusNode = focus.hover >= 0 ? focus.hover : focus.selected;
  s.edges.forEach((e, k) => {
    const kind = e.kind;
    color.push(
      kind === 'member_of' || kind === 'admin' ? theme.colors.edgeStructural : theme.edge[kind],
    );
    const choke = ix.chokeByEdge.get(e.id)?.paths_cut ?? 1;
    width[k] = 1.25 + Math.min(4, Math.log2(Math.max(1, choke)));
    dash.set(
      dashArray(e.status === 'conditional' ? conditionalDash : e.latent ? '1 4' : edgeDash[kind]),
      k * 4,
    );
    const a = s.edgeFrom[k] ?? 0;
    const b = s.edgeTo[k] ?? 0;
    let fl = 0;
    if ((nodes.flags[a] ?? 0) & NodeFlag.hidden || (nodes.flags[b] ?? 0) & NodeFlag.hidden)
      fl |= EdgeFlag.hidden;
    if (focus.pathEdges.size) {
      fl |= focus.pathEdges.has(k) ? EdgeFlag.highlight : EdgeFlag.dimmed;
    } else if (focusNode >= 0) {
      fl |= a === focusNode || b === focusNode ? EdgeFlag.highlight : EdgeFlag.dimmed;
    }
    flags[k] = fl;
  });
  return { from: s.edgeFrom, to: s.edgeTo, color, width, dash, flags };
}

/** Meta-nodes for semantic zoom: one per account (or group) with the
 * centroid of its visible nodes and the count. */
export function metaNodes(
  s: Scene,
  x: Float32Array,
  y: Float32Array,
  f: Filters,
): { key: string; x: number; y: number; count: number; tier0: number }[] {
  const acc = new Map<string, { x: number; y: number; count: number; tier0: number }>();
  s.nodes.forEach((n, i) => {
    if (!visible(n, f)) return;
    const key = n.group ?? (n.account || n.kind);
    const a = acc.get(key) ?? { x: 0, y: 0, count: 0, tier0: 0 };
    a.x += x[i] ?? 0;
    a.y += y[i] ?? 0;
    a.count++;
    if (n.tier === 0) a.tier0++;
    acc.set(key, a);
  });
  return [...acc.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([key, a]) => ({
      key,
      x: a.x / a.count,
      y: a.y / a.count,
      count: a.count,
      tier0: a.tier0,
    }));
}
