import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { emptyFilters, to, type Route } from '../../state/route';
import { Findings } from './Findings';
import { csvCell, filterFindings, toCSV, windowRange } from './model';

const ix = buildIndexes(vulnerable);

describe('filterFindings', () => {
  it('filters by severity, rule, text and suppression', () => {
    const all = filterFindings(ix, emptyFilters);
    expect(all.length).toBe(vulnerable.findings.filter((f) => !f.suppressed).length);
    expect(all[0]?.severity).toBe('critical');
    const crit = filterFindings(ix, { ...emptyFilters, severities: ['critical'] });
    expect(crit.every((f) => f.severity === 'critical')).toBe(true);
    const rule = filterFindings(ix, { ...emptyFilters, rules: ['EL-PE-022'] });
    expect(rule.length).toBeGreaterThan(0);
    expect(rule.every((f) => f.rule_id === 'EL-PE-022')).toBe(true);
    expect(filterFindings(ix, { ...emptyFilters, text: 'pe022-attacker' }).length).toBeGreaterThan(
      0,
    );
    expect(filterFindings(ix, { ...emptyFilters, text: 'no-such-thing-xyz' })).toEqual([]);
    expect(
      filterFindings(ix, { ...emptyFilters, tiers: [1], kinds: ['user'] }).every(
        (f) => ix.nodes.get(f.node_id ?? '')?.tier === 1,
      ),
    ).toBe(true);
    expect(filterFindings(ix, { ...emptyFilters, accounts: ['999999999999'] })).toEqual([]);
  });
  it('sorts by rule and subject', () => {
    const byRule = filterFindings(ix, emptyFilters, 'rule').map((f) => f.rule_id);
    expect([...byRule].sort()).toEqual(byRule);
    expect(filterFindings(ix, emptyFilters, 'subject').length).toBe(byRule.length);
  });
});

describe('csv', () => {
  it('escapes and neutralizes formulas', () => {
    expect(csvCell('plain')).toBe('plain');
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('-1')).toBe("'-1");
    const csv = toCSV(ix, filterFindings(ix, emptyFilters).slice(0, 3));
    expect(csv.split('\r\n')[0]).toBe(
      'id,severity,rule_id,title,subject,message,policy,statement_index,path_id,suppressed',
    );
    expect(csv.split('\r\n').length).toBe(5);
  });
});

describe('windowRange', () => {
  it('renders only the visible rows plus overscan', () => {
    expect(windowRange(0, 560, 56, 1000)).toEqual([0, 18]);
    expect(windowRange(5600, 560, 56, 1000)).toEqual([92, 118]);
    expect(windowRange(0, 560, 56, 3)).toEqual([0, 3]);
  });
});

describe('Findings view', () => {
  it('renders, filters through the route and selects rows', () => {
    let route: Route = to('findings');
    const update = vi.fn((patch: (r: Route) => Route) => {
      route = patch(route);
    });
    const { rerender } = render(
      <ThemeProvider name="light">
        <Findings
          ix={ix}
          route={route}
          pseudonyms={false}
          navigate={() => undefined}
          update={update}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('region', { name: 'Findings table' })).toBeTruthy();
    fireEvent.click(screen.getByRole('checkbox', { name: 'critical' }));
    expect(route.filters.severities).toEqual(['critical']);
    rerender(
      <ThemeProvider name="light">
        <Findings
          ix={ix}
          route={route}
          pseudonyms={true}
          navigate={() => undefined}
          update={update}
        />
      </ThemeProvider>,
    );
    expect(screen.getByText(/finding\(s\)/).textContent).toMatch(/^\d+ finding/);
    const firstRow = screen.getAllByRole('row')[1];
    if (firstRow) fireEvent.click(firstRow);
    expect(route.sel).toMatch(/^f_/);
    expect(screen.getByRole<HTMLButtonElement>('button', { name: 'Export CSV' }).disabled).toBe(
      true,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Rule' }));
  });
});
