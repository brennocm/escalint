import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { Analysis, Edge, Node } from '../../contract/analysis';
import { buildIndexes } from '../../data/indexes';
import { vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { to, type Route } from '../../state/route';
import { barycentric, crossings, reachLayout, rings, totalCrossings } from './layout';
import { Reach } from './Reach';

const hex = (n: number): string => n.toString(16).padStart(16, '0');
function node(i: number): Node {
  return {
    id: `n_${hex(i)}`,
    kind: 'role',
    arn: null,
    name: `r${String(i)}`,
    account: '111111111111',
    path: null,
    tags: {},
    tier: 3,
    tier_conditional: false,
    service_linked: false,
    blast: null,
    last_used: null,
    flags: [],
    group: null,
  };
}
function edge(from: number, to: number): Edge {
  return {
    id: `e_${hex(from * 1000 + to)}`,
    from: `n_${hex(from)}`,
    to: `n_${hex(to)}`,
    kind: 'assume',
    rule_ids: [],
    pathfinding_ids: [],
    status: 'allowed',
    required_actions: [],
    evidence: [],
    conditions_unevaluated: [],
    prerequisites_unverified: [],
    latent: false,
    actor: null,
    attack: [],
    detection: {
      events: [],
      blind_spots: [],
      requires_data_events: false,
      status: 'verified',
      visibility: 'visible',
    },
  };
}
/** Center 0 → ring 1 {1..4} → ring 2 where each ring-1 node's children
 * are listed far from it in ID order, so the naive order crosses. */
function crossingGraph(): Analysis {
  const nodes = Array.from({ length: 9 }, (_, i) => node(i));
  const edges = [
    edge(0, 1),
    edge(0, 2),
    edge(0, 3),
    edge(0, 4),
    edge(1, 8),
    edge(2, 7),
    edge(3, 6),
    edge(4, 5),
  ];
  return { ...vulnerable, nodes, edges, paths: [], findings: [], choke_points: [], fix_plan: [] };
}

describe('reach layout', () => {
  it('builds rings by hop in both directions', () => {
    const ix = buildIndexes(crossingGraph());
    const r = rings(ix, 'n_' + hex(0), 'out', 4, 60);
    expect(r.rings.map((x) => x.length)).toEqual([1, 4, 4]);
    expect(r.edges).toHaveLength(8);
    const back = rings(ix, 'n_' + hex(8), 'in', 4, 60);
    expect(back.rings.map((x) => x.length)).toEqual([1, 1, 1]);
    const capped = rings(ix, 'n_' + hex(0), 'out', 4, 2);
    expect(capped.hidden).toBe(2); // ring 2 only sees the kept nodes
  });
  it('reduces crossings with the barycenter heuristic', () => {
    const ix = buildIndexes(crossingGraph());
    const r = rings(ix, 'n_' + hex(0), 'out', 4, 60);
    const before = totalCrossings(r.rings, r.edges);
    const after = totalCrossings(barycentric(r.rings, r.edges), r.edges);
    expect(before).toBeGreaterThan(0);
    expect(after).toBe(0);
  });
  it('never makes the vulnerable account worse', () => {
    const ix = buildIndexes(vulnerable);
    for (const n of vulnerable.nodes.slice(0, 20)) {
      for (const dir of ['in', 'out'] as const) {
        const r = rings(ix, n.id, dir, 4, 60);
        expect(totalCrossings(barycentric(r.rings, r.edges), r.edges)).toBeLessThanOrEqual(
          totalCrossings(r.rings, r.edges),
        );
      }
    }
  });
  it('counts crossings', () => {
    const pos = new Map([
      ['a', 0],
      ['b', 1],
      ['x', 0],
      ['y', 1],
    ]);
    expect(
      crossings(
        [
          { id: '1', from: 'a', to: 'y' },
          { id: '2', from: 'b', to: 'x' },
        ],
        pos,
      ),
    ).toBe(1);
    expect(
      crossings(
        [
          { id: '1', from: 'a', to: 'x' },
          { id: '2', from: 'b', to: 'y' },
        ],
        pos,
      ),
    ).toBe(0);
  });
  it('places rings at fixed radii, deterministically', () => {
    const ix = buildIndexes(crossingGraph());
    const l = reachLayout(ix, 'n_' + hex(0), 'out');
    for (const n of l.nodes) expect(Math.round(Math.hypot(n.x, n.y))).toBe(n.ring * 110);
    expect(reachLayout(ix, 'n_' + hex(0), 'out')).toEqual(l);
  });
});

describe('Reach view', () => {
  it('renders, switches direction and recenters', () => {
    const ix = buildIndexes(vulnerable);
    const start = vulnerable.paths[0]?.source ?? '';
    let route: Route = { ...to('reach', start) };
    const update = vi.fn((p: (r: Route) => Route) => {
      route = p(route);
    });
    const nav = vi.fn();
    render(
      <ThemeProvider name="light">
        <Reach ix={ix} route={route} pseudonyms={false} navigate={nav} update={update} />
      </ThemeProvider>,
    );
    expect(screen.getByRole('group', { name: 'Reach diagram' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Who can reach it' }));
    expect(route.dir).toBe('in');
    const nodes = screen.getAllByRole('button', { name: /hop\(s\)$/ });
    const outer = nodes[1];
    if (!outer) throw new Error('no outer node');
    fireEvent.keyDown(outer, { key: 'Enter' });
    expect(nav).toHaveBeenCalledWith(expect.objectContaining({ view: 'reach' }));
    fireEvent.keyDown(outer, { key: ' ' });
    expect(route.sel).toMatch(/^n_/);
    fireEvent.keyDown(nodes[0] as Element, { key: 'ArrowDown' });
    expect(screen.getByRole('heading', { name: 'By distance' })).toBeTruthy();
  });
});
