import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { themes } from '../../design/tokens';
import { SpatialGrid } from '../../layout/spatial';
import { emptyFilters, to, type Route } from '../../state/route';
import { Atlas, degradationNotice } from './Atlas';
import { dashArray, EdgeFlag, NodeFlag } from './renderer';
import {
  buildScene,
  edgeAttrs,
  metaNodes,
  neighborhood,
  nodeAttrs,
  shortestPath,
  visible,
} from './scene';

const ix = buildIndexes(vulnerable);
const scene = buildScene(ix);
const n = scene.nodes.length;
const xs = Float32Array.from({ length: n }, (_, i) => i * 10);
const ys = Float32Array.from({ length: n }, (_, i) => (i % 7) * 10);

describe('scene', () => {
  it('indexes nodes in ID order with usable adjacency', () => {
    expect(scene.nodes.map((x) => x.id)).toEqual([...scene.nodes.map((x) => x.id)].sort());
    let usable = 0;
    for (const list of scene.out) usable += list.length;
    expect(usable).toBe(vulnerable.edges.filter((e) => e.kind !== 'member_of' && !e.latent).length);
  });
  it('finds shortest paths in either direction', () => {
    const p = vulnerable.paths.find((x) => x.length >= 1);
    if (!p) throw new Error('fixture');
    const a = scene.index.get(p.source) ?? -1;
    const b = scene.index.get(p.target) ?? -1;
    const forward = shortestPath(scene, a, b);
    expect(forward.length).toBeGreaterThan(0);
    expect(forward.length).toBeLessThanOrEqual(p.length);
    expect(shortestPath(scene, b, a)).toEqual(forward);
    expect(shortestPath(scene, a, a)).toEqual([]);
    expect(neighborhood(scene, a).has(a)).toBe(true);
  });
  it('sets flags for filters, focus and paths', () => {
    const t0 = scene.nodes.findIndex((x) => x.tier === 0 && x.kind !== 'tier0_sink');
    const focus = { hover: -1, selected: t0, pathEdges: new Set<number>() };
    const nodes = nodeAttrs(
      scene,
      ix,
      themes.light,
      xs,
      ys,
      { ...emptyFilters, tiers: [0] },
      focus,
    );
    scene.nodes.forEach((node, i) => {
      expect(((nodes.flags[i] ?? 0) & NodeFlag.hidden) !== 0).toBe(
        !visible(node, { ...emptyFilters, tiers: [0] }),
      );
    });
    expect((nodes.flags[t0] ?? 0) & NodeFlag.selected).toBeTruthy();
    expect((nodes.flags[t0] ?? 0) & NodeFlag.tier0).toBeTruthy();
    const edges = edgeAttrs(scene, ix, themes.light, nodes, focus);
    expect(edges.dash.length).toBe(scene.edges.length * 4);
    expect([...edges.flags].some((f) => f & EdgeFlag.hidden)).toBe(true);
    const path = new Set([0]);
    const withPath = edgeAttrs(
      scene,
      ix,
      themes.dark,
      nodeAttrs(scene, ix, themes.dark, xs, ys, emptyFilters, {
        hover: -1,
        selected: -1,
        pathEdges: path,
      }),
      { hover: -1, selected: -1, pathEdges: path },
    );
    expect((withPath.flags[0] ?? 0) & EdgeFlag.highlight).toBeTruthy();
  });
  it('aggregates meta-nodes per account', () => {
    const meta = metaNodes(scene, xs, ys, emptyFilters);
    expect(meta.reduce((s, m) => s + m.count, 0)).toBe(n);
    expect(meta.some((m) => m.key === '111111111111' && m.tier0 > 0)).toBe(true);
  });
  it('parses dash arrays', () => {
    expect(dashArray('none')).toEqual([0, 0, 0, 0]);
    expect(dashArray('8 4')).toEqual([8, 4, 0, 0]);
    expect(dashArray('10 3 2 3')).toEqual([10, 3, 2, 3]);
  });
});

describe('SpatialGrid', () => {
  it('finds the nearest visible point', () => {
    const g = new SpatialGrid([0, 100, 105], [0, 0, 0], 40);
    expect(g.nearest(101, 1, 20)).toBe(1);
    expect(g.nearest(104, 0, 20, (i) => i === 2)).toBe(1);
    expect(g.nearest(500, 500, 20)).toBe(-1);
  });
});

describe('Atlas view', () => {
  it('falls back to the table without WebGL2 and filters through the route', async () => {
    let route: Route = to('atlas');
    const update = vi.fn((p: (r: Route) => Route) => {
      route = p(route);
    });
    render(
      <ThemeProvider name="light">
        <Atlas
          ix={ix}
          route={route}
          pseudonyms={false}
          navigate={() => undefined}
          update={update}
        />
      </ThemeProvider>,
    );
    expect(await screen.findByText(/needs WebGL2/)).toBeTruthy();
    fireEvent.click(screen.getByRole('checkbox', { name: '0' }));
    expect(route.filters.tiers).toEqual([0]);
    fireEvent.click(screen.getByRole('button', { name: 'Critical paths' }));
    expect(
      screen.getByRole('button', { name: 'Critical paths' }).getAttribute('aria-pressed'),
    ).toBe('true');
    const row = screen.getAllByRole('button').find((b) => b.className === 'link-button');
    if (row) fireEvent.click(row);
    expect(route.sel === null || route.sel.startsWith('n_')).toBe(true);
    fireEvent.keyDown(screen.getByRole('application'), { key: '+' });
    expect(screen.queryByText(/Large graph/)).toBeNull();
  });
  it('explains how it degrades on large graphs', () => {
    expect(degradationNotice(10_000)).toBeNull();
    expect(degradationNotice(50_000)).toMatch(/^Large graph: 50,000 nodes\. .*meta-node/);
  });
});
