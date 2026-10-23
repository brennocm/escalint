import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { emptyFilters, to, type Route } from '../../state/route';
import { Exposure } from './Exposure';
import { buildMatrix, cellAt, jaccard, seriate } from './model';

const ix = buildIndexes(vulnerable);

describe('exposure matrix', () => {
  it('has one row per principal and consistent totals', () => {
    const m = buildMatrix(ix);
    expect(m.rows.length).toBe(
      vulnerable.nodes.filter((n) => ['user', 'role', 'group'].includes(n.kind)).length,
    );
    let filled = 0;
    for (let r = 0; r < m.rows.length; r++)
      for (let c = 0; c < m.services.length; c++) if (cellAt(m, r, c) >= 0) filled++;
    expect(m.rowTotals.reduce((s, x) => s + x, 0)).toBe(filled);
    expect(m.colTotals.reduce((s, x) => s + x, 0)).toBe(filled);
    const freq = m.colTotals;
    expect([...freq].sort((a, b) => b - a)).toEqual(freq);
  });
  it('keeps identical profiles adjacent', () => {
    const m = buildMatrix(ix);
    const sig = m.rows.map((_, r) =>
      Array.from({ length: m.services.length }, (_, c) => cellAt(m, r, c)).join(','),
    );
    const seen = new Set<string>();
    for (let r = 0; r < sig.length; r++) {
      const s = sig[r] ?? '';
      if (r > 0 && sig[r - 1] === s) continue;
      expect(seen.has(s)).toBe(false); // a profile never reappears after a different one
      seen.add(s);
    }
  });
  it('chains nearest neighbors', () => {
    const sets = new Map([
      ['a', new Set(['x', 'y', 'z'])],
      ['b', new Set(['p'])],
      ['c', new Set(['x', 'y'])],
      ['d', new Set(['p', 'q'])],
    ]);
    expect(seriate(['a', 'b', 'c', 'd'], sets)).toEqual(['a', 'c', 'b', 'd']);
    expect(jaccard(new Set(), new Set())).toBe(0);
    expect(jaccard(new Set(['a']), new Set(['b']))).toBe(1);
  });
  it('filters by tier', () => {
    expect(buildMatrix(ix, (n) => n.tier === 0).rows.every((n) => n.tier === 0)).toBe(true);
  });
});

describe('Exposure view', () => {
  it('selects a principal from a cell and has a table view', () => {
    let route: Route = to('exposure');
    const update = vi.fn((p: (r: Route) => Route) => {
      route = p(route);
    });
    render(
      <ThemeProvider name="light">
        <Exposure
          ix={ix}
          route={route}
          pseudonyms={false}
          navigate={() => undefined}
          update={update}
        />
      </ThemeProvider>,
    );
    const canvas = screen.getByTestId('exposure-canvas');
    canvas.getBoundingClientRect = () => ({
      left: 0,
      top: 0,
      right: 0,
      bottom: 0,
      width: 0,
      height: 0,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    fireEvent.click(canvas, { clientX: 220 + 5, clientY: 110 + 5 });
    expect(route.sel).toMatch(/^n_/);
    expect(screen.getByText('Table view')).toBeTruthy();
  });
  it('shows an empty state when the filter matches nothing', () => {
    render(
      <ThemeProvider name="dark">
        <Exposure
          ix={buildIndexes({ ...vulnerable, nodes: [] })}
          route={{ ...to('exposure'), filters: { ...emptyFilters, tiers: [0] } }}
          pseudonyms
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('heading', { name: 'No principals' })).toBeTruthy();
  });
});
