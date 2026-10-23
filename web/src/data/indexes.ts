import type {
  Analysis,
  Edge,
  Finding,
  Node,
  Path,
  Rule,
  ChokePoint,
  FixStep,
} from '../contract/analysis';

type Tier = 0 | 1 | 2 | 3;

/** Indexes built once per analysis: every view reads through them. */
export interface Indexes {
  readonly analysis: Analysis;
  readonly nodes: ReadonlyMap<string, Node>;
  readonly edges: ReadonlyMap<string, Edge>;
  readonly paths: ReadonlyMap<string, Path>;
  readonly findings: ReadonlyMap<string, Finding>;
  readonly rules: ReadonlyMap<string, Rule>;
  /** Edges leaving / entering a node, sorted by the other end then ID. */
  readonly out: ReadonlyMap<string, readonly Edge[]>;
  readonly in: ReadonlyMap<string, readonly Edge[]>;
  readonly byTier: ReadonlyMap<Tier, readonly Node[]>;
  readonly byAccount: ReadonlyMap<string, readonly Node[]>;
  readonly findingsByNode: ReadonlyMap<string, readonly Finding[]>;
  readonly findingsByEdge: ReadonlyMap<string, readonly Finding[]>;
  /** Paths that start at or pass through a node. */
  readonly pathsByNode: ReadonlyMap<string, readonly Path[]>;
  readonly pathsByEdge: ReadonlyMap<string, readonly Path[]>;
  readonly chokeByEdge: ReadonlyMap<string, ChokePoint>;
  readonly fixByEdge: ReadonlyMap<string, FixStep>;
  /** Analyzed accounts (external ones only appear in byAccount). */
  readonly accounts: readonly string[];
  /** Largest reachable_principals, for node size scales. */
  readonly maxReach: number;
}

function push<K, V>(m: Map<K, V[]>, k: K, v: V): void {
  const list = m.get(k);
  if (list) {
    list.push(v);
  } else {
    m.set(k, [v]);
  }
}

function byId<T extends { readonly id: string }>(list: readonly T[]): Map<string, T> {
  return new Map(list.map((x) => [x.id, x]));
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export function buildIndexes(a: Analysis): Indexes {
  const out = new Map<string, Edge[]>();
  const inn = new Map<string, Edge[]>();
  for (const e of a.edges) {
    push(out, e.from, e);
    push(inn, e.to, e);
  }
  for (const list of out.values()) list.sort((x, y) => cmp(x.to, y.to) || cmp(x.id, y.id));
  for (const list of inn.values()) list.sort((x, y) => cmp(x.from, y.from) || cmp(x.id, y.id));

  const byTier = new Map<Tier, Node[]>();
  const byAccount = new Map<string, Node[]>();
  let maxReach = 0;
  for (const n of a.nodes) {
    push(byTier, n.tier as Tier, n);
    if (n.account) push(byAccount, n.account, n);
    maxReach = Math.max(maxReach, n.blast?.reachable_principals ?? 0);
  }
  const findingsByNode = new Map<string, Finding[]>();
  const findingsByEdge = new Map<string, Finding[]>();
  for (const f of a.findings) {
    if (f.node_id) push(findingsByNode, f.node_id, f);
    if (f.edge_id) push(findingsByEdge, f.edge_id, f);
  }
  const pathsByNode = new Map<string, Path[]>();
  const pathsByEdge = new Map<string, Path[]>();
  for (const p of a.paths) {
    for (const n of new Set(p.nodes)) push(pathsByNode, n, p);
    for (const e of new Set(p.edges)) push(pathsByEdge, e, p);
  }
  return {
    analysis: a,
    nodes: byId(a.nodes),
    edges: byId(a.edges),
    paths: byId(a.paths),
    findings: byId(a.findings),
    rules: byId(a.rules),
    out,
    in: inn,
    byTier,
    byAccount,
    findingsByNode,
    findingsByEdge,
    pathsByNode,
    pathsByEdge,
    chokeByEdge: new Map(a.choke_points.map((c) => [c.edge_id, c])),
    fixByEdge: new Map(a.fix_plan.map((s) => [s.edge_id, s])),
    accounts: [...a.snapshot.accounts].sort(cmp),
    maxReach,
  };
}

/** Display label of a node: name for principals, account for sinks. */
export function nodeLabel(n: Node): string {
  if (n.kind === 'tier0_sink') return `Effective admin (${n.account})`;
  return n.name !== '' ? n.name : (n.arn ?? n.id);
}

/** Severity rank: 0 critical … 4 info. */
export function severityRank(s: string): number {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const i = order.indexOf(s);
  return i < 0 ? order.length : i;
}

export function isPrincipal(n: Node): boolean {
  return n.kind === 'user' || n.kind === 'role' || n.kind === 'group';
}
