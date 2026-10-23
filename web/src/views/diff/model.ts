import type { Edge, Node, Path } from '../../contract/analysis';
import type { Indexes } from '../../data/indexes';
import { forceLayout } from '../../layout/force';

export type Change = 'added' | 'removed' | 'same';

export interface DiffScene {
  readonly nodes: readonly {
    readonly node: Node;
    readonly change: Change;
    readonly x: number;
    readonly y: number;
  }[];
  readonly edges: readonly { readonly edge: Edge; readonly change: Change }[];
  readonly addedPaths: readonly Path[];
  readonly removedPaths: readonly Path[];
}

/** The changed part of the graph: endpoints of added and removed edges,
 * laid out once over the union of both sides so a node keeps its position
 * whatever side it is on (the seed comes from the stable IDs). */
export function diffScene(ix: Indexes): DiffScene | null {
  const d = ix.analysis.diff;
  if (!d) return null;
  const removedObjects = d.removed.objects;
  const addedEdges = new Set(d.added.edges);
  const nodes = new Map<string, { node: Node; change: Change }>();
  const addedNodes = new Set(d.added.nodes);
  for (const n of ix.analysis.nodes)
    nodes.set(n.id, { node: n, change: addedNodes.has(n.id) ? 'added' : 'same' });
  for (const n of removedObjects?.nodes ?? []) nodes.set(n.id, { node: n, change: 'removed' });
  const edges: { edge: Edge; change: Change }[] = [];
  for (const id of addedEdges) {
    const e = ix.edges.get(id);
    if (e) edges.push({ edge: e, change: 'added' });
  }
  for (const e of removedObjects?.edges ?? []) edges.push({ edge: e, change: 'removed' });
  edges.sort((a, b) => (a.edge.id < b.edge.id ? -1 : 1));
  const touched = [...new Set(edges.flatMap((e) => [e.edge.from, e.edge.to]))]
    .filter((id) => nodes.has(id))
    .sort();
  const index = new Map(touched.map((id, i) => [id, i]));
  const layout = forceLayout({
    ids: touched,
    edges: edges
      .filter((e) => index.has(e.edge.from) && index.has(e.edge.to))
      .map((e) => [index.get(e.edge.from) ?? 0, index.get(e.edge.to) ?? 0] as const),
    groups: touched.map(() => 'g'),
    iterations: 150,
  });
  return {
    nodes: touched.map((id, i) => {
      const entry = nodes.get(id);
      if (!entry) throw new Error('unreachable');
      return { ...entry, x: layout.x[i] ?? 0, y: layout.y[i] ?? 0 };
    }),
    edges,
    addedPaths: d.added.paths
      .map((id) => ix.paths.get(id))
      .filter((p): p is Path => p !== undefined),
    removedPaths: removedObjects?.paths ?? [],
  };
}
