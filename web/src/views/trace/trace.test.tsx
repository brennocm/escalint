import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { to, type Route } from '../../state/route';
import { serializeSVG } from '../export';
import { alternatives, chokeWidth, neighbor, traceLayout } from './layout';
import { Trace } from './Trace';

const ix = buildIndexes(vulnerable);
// A source with several paths exercises the alternative rows.
const multi =
  vulnerable.paths.find((p) => vulnerable.paths.filter((q) => q.source === p.source).length > 1) ??
  vulnerable.paths[0];
if (!multi) throw new Error('fixture has no path');

describe('trace layout', () => {
  it('puts the chosen path first and aligns steps in columns', () => {
    const l = traceLayout(ix, multi);
    expect(l.rows[0]).toBe(multi);
    expect(l.cards.filter((c) => c.row === 0).map((c) => c.id)).toEqual(multi.nodes);
    for (const c of l.cards) expect(c.x).toBe(16 + c.col * (196 + 150));
    expect(l.edges.filter((e) => e.row === 0)).toHaveLength(multi.edges.length);
    expect(traceLayout(ix, multi)).toEqual(l);
    expect(l.width).toBeGreaterThan(196);
    for (const a of alternatives(ix, multi)) expect(a.source).toBe(multi.source);
  });
  it('navigates cards with arrows', () => {
    const l = traceLayout(ix, multi);
    const start = l.cards[0];
    if (!start) throw new Error('no cards');
    expect(neighbor(l, start, 'ArrowRight')?.col).toBe(1);
    expect(neighbor(l, start, 'ArrowLeft')).toBeUndefined();
    expect(neighbor(l, start, 'ArrowUp')).toBeUndefined();
    if (l.rows.length > 1) expect(neighbor(l, start, 'ArrowDown')?.row).toBe(1);
    expect(neighbor(l, start, 'x')).toBeUndefined();
  });
  it('scales choke points logarithmically', () => {
    expect(chokeWidth(1)).toBe(1.75);
    expect(chokeWidth(4)).toBe(3.75);
    expect(chokeWidth(10_000)).toBe(5.75);
  });
});

describe('Trace view', () => {
  it('renders cards and steps, opens the explainer on an edge', () => {
    let route: Route = to('path', multi.id);
    const update = vi.fn((patch: (r: Route) => Route) => {
      route = patch(route);
    });
    const ui = () => (
      <ThemeProvider name="light">
        <Trace
          ix={ix}
          route={route}
          pseudonyms={false}
          navigate={() => undefined}
          update={update}
        />
      </ThemeProvider>
    );
    const { rerender } = render(ui());
    expect(screen.getByRole('group', { name: 'Escalation path diagram' })).toBeTruthy();
    const edgeButton = screen.getAllByRole('button', { name: /edge: .*policy explainer/ })[0];
    if (!edgeButton) throw new Error('no edge');
    fireEvent.keyDown(edgeButton, { key: 'Enter' });
    expect(route.sel).toMatch(/^e_/);
    rerender(ui());
    expect(screen.getByRole('region', { name: 'Policy explainer' })).toBeTruthy();
    const cards = screen.getAllByRole('button', { name: /tier \d/ });
    cards[0]?.focus();
    fireEvent.keyDown(cards[0] as Element, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(cards[1]);
    fireEvent.keyDown(cards[1] as Element, { key: ' ' });
    expect(route.sel).toMatch(/^n_/);
    const svg = screen.getByRole('group', {
      name: 'Escalation path diagram',
    }) as unknown as SVGSVGElement;
    const text = serializeSVG(svg);
    expect(text).toContain('xmlns="http://www.w3.org/2000/svg"');
    expect(text).not.toContain('tabindex');
  });
  it('shows an empty state for unknown paths', () => {
    render(
      <ThemeProvider name="dark">
        <Trace
          ix={ix}
          route={to('path', 'p_0000000000000000')}
          pseudonyms={true}
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('heading', { name: 'Path not found' })).toBeTruthy();
  });
});
