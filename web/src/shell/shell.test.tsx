import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { buildIndexes } from '../data/indexes';
import { vulnerable } from '../data/fixtures';
import { ThemeProvider } from '../design/theme';
import { candidates, routeFor } from './candidates';
import { DetailsPanel } from './DetailsPanel';
import { keyAction } from './keys';
import { Legend } from './Legend';
import { displayAccount, displayArn, displayName } from './names';

const ix = buildIndexes(vulnerable);
const user = vulnerable.nodes.find((n) => n.kind === 'user' && n.blast);
const sink = vulnerable.nodes.find((n) => n.kind === 'tier0_sink');

describe('names', () => {
  it('hides names behind stable pseudonyms', () => {
    if (!user || !sink) throw new Error('fixture');
    expect(displayName(user, false)).toBe(user.name);
    expect(displayName(user, true)).toBe(`user ${user.id.slice(2, 8)}`);
    expect(displayName(sink, true)).toContain('Effective admin');
    expect(displayArn(user, true)).toBe(user.id);
    expect(displayAccount('111111111111', true)).toBe('acct 1111');
    expect(displayAccount('111111111111', false)).toBe('111111111111');
  });
});

describe('candidates', () => {
  it('covers views, nodes, rules, techniques and paths', () => {
    const list = candidates(ix, false);
    const kinds = new Set(list.map((c) => c.kind));
    expect([...kinds].sort()).toEqual(['node', 'path', 'rule', 'view']);
    expect(list.some((c) => c.label === 'T1098.003')).toBe(true);
    expect(
      list.some((c) => c.kind === 'node' && c.text.includes('arn:aws:iam::111111111111')),
    ).toBe(true);
    const hidden = candidates(ix, true).filter((c) => c.kind === 'node');
    expect(hidden.every((c) => !c.text.includes('arn:aws'))).toBe(true);
  });
  it('maps choices to routes', () => {
    const [view, node, rule, path] = [
      { key: 'view:atlas', kind: 'view' as const },
      { key: 'n_0123456789abcdef', kind: 'node' as const },
      { key: 'EL-PE-001:T1098.003', kind: 'rule' as const },
      { key: 'p_0123456789abcdef', kind: 'path' as const },
    ].map((c) => routeFor({ ...c, text: '', label: '', detail: '', tier: 4 }));
    expect(view?.view).toBe('atlas');
    expect(node).toMatchObject({
      view: 'reach',
      id: 'n_0123456789abcdef',
      sel: 'n_0123456789abcdef',
    });
    expect(rule?.filters.rules).toEqual(['EL-PE-001']);
    expect(path).toMatchObject({ view: 'path', id: 'p_0123456789abcdef' });
  });
});

describe('keyAction', () => {
  const k = (key: string, mods: Partial<KeyboardEvent> = {}) => ({
    key,
    ctrlKey: false,
    metaKey: false,
    altKey: false,
    ...mods,
  });
  it('maps shortcuts', () => {
    expect(keyAction(k('k', { ctrlKey: true }), true, '').action).toEqual({ type: 'palette' });
    expect(keyAction(k('K', { metaKey: true }), false, '').action).toEqual({ type: 'palette' });
    expect(keyAction(k('?'), false, '').action).toEqual({ type: 'help' });
    expect(keyAction(k('?'), true, '').action).toBeNull();
    expect(keyAction(k('Escape'), true, '').action).toEqual({ type: 'escape' });
    const g = keyAction(k('g'), false, '');
    expect(g.pending).toBe('g');
    expect(keyAction(k('x'), false, g.pending).action).toEqual({ type: 'go', view: 'fix' });
    expect(keyAction(k('z'), false, 'g').action).toBeNull();
    expect(keyAction(k('z'), false, '').action).toBeNull();
    expect(keyAction(k('t', { altKey: true }), false, '').action).toBeNull();
  });
});

describe('DetailsPanel', () => {
  it('shows a node with its findings and actions', () => {
    if (!user) throw new Error('fixture');
    const nav = vi.fn();
    render(
      <ThemeProvider name="light">
        <DetailsPanel
          ix={ix}
          sel={user.id}
          pseudonyms={false}
          onNavigate={nav}
          onClose={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('heading', { level: 3 }).textContent).toContain(user.name);
    fireEvent.click(screen.getByRole('button', { name: 'Who reaches it' }));
    expect(nav).toHaveBeenCalledWith(
      expect.objectContaining({ view: 'reach', dir: 'in', id: user.id }),
    );
  });
  it('shows edges, paths and findings', () => {
    const edge = vulnerable.edges.find(
      (e) => e.conditions_unevaluated.length > 0 || e.rule_ids.length > 0,
    );
    const path = vulnerable.paths[0];
    const finding = vulnerable.findings[0];
    if (!edge || !path || !finding) throw new Error('fixture');
    for (const sel of [edge.id, path.id, finding.id, 'n_ffffffffffffffff']) {
      const { unmount } = render(
        <ThemeProvider name="dark">
          <DetailsPanel
            ix={ix}
            sel={sel}
            pseudonyms={true}
            onNavigate={() => undefined}
            onClose={() => undefined}
          />
        </ThemeProvider>,
      );
      expect(screen.getByRole('complementary', { name: 'Details' })).toBeTruthy();
      unmount();
    }
  });
});

describe('Legend', () => {
  it('collapses', () => {
    render(
      <ThemeProvider name="light">
        <Legend />
      </ThemeProvider>,
    );
    const toggle = screen.getByRole('button', { name: 'Legend' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    expect(screen.getByText('Tier 0: effective administrator')).toBeTruthy();
    fireEvent.click(toggle);
    expect(screen.queryByText('Tier 0: effective administrator')).toBeNull();
  });
});

describe('DemoBanner', () => {
  it('says the data is synthetic and switches datasets', async () => {
    const { DemoBanner } = await import('./DemoBanner');
    render(<DemoBanner />);
    expect(screen.getByRole('note').textContent).toContain('synthetic');
    expect(screen.getByRole('combobox', { name: 'Dataset' })).toBeTruthy();
  });
});
