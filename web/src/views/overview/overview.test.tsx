import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { hardened, vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { defaultRoute } from '../../state/route';
import { overview, pathVisibility } from './model';
import { Overview } from './Overview';

describe('overview model', () => {
  it('summarizes the vulnerable account', () => {
    const ix = buildIndexes(vulnerable);
    const m = overview(ix);
    const principals = vulnerable.nodes.filter((n) =>
      ['user', 'role', 'group'].includes(n.kind),
    ).length;
    expect(m.principalsByTier.reduce((s, x) => s + x, 0)).toBe(principals);
    expect(m.criticalPaths).toBe(vulnerable.paths.filter((p) => p.severity === 'critical').length);
    expect(m.worstPaths.length).toBeLessThanOrEqual(5);
    expect(m.worstPaths[0]?.severity).toBe('critical');
    expect(m.topFixes[0]?.order).toBe(1);
    expect(m.externalAccounts).toBeGreaterThan(0);
    for (const p of vulnerable.paths)
      expect(['visible', 'partial', 'blind']).toContain(pathVisibility(ix, p));
  });
  it('is empty for the hardened account', () => {
    const m = overview(buildIndexes(hardened));
    expect(Object.values(m.findingsBySeverity).every((n) => n === 0)).toBe(true);
    // The only path is the intended SSO entry into the admin role.
    expect(m.topFixes.length).toBeLessThanOrEqual(1);
  });
});

describe('Overview', () => {
  it('links every number to a filtered view', () => {
    const ix = buildIndexes(vulnerable);
    render(
      <ThemeProvider name="light">
        <Overview
          ix={ix}
          route={defaultRoute}
          pseudonyms={false}
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('link', { name: /Tier 0 — admin/ }).getAttribute('href')).toBe(
      '#/atlas?tier=0',
    );
    const hrefs = screen.getAllByRole('link').map((l) => l.getAttribute('href'));
    expect(hrefs).toContain('#/findings?sev=critical');
    expect(hrefs).toContain('#/fix');
    expect(screen.getAllByRole('img', { name: /CloudTrail visibility/ }).length).toBeGreaterThan(0);
    expect(screen.getByRole('heading', { name: 'Worst paths' })).toBeTruthy();
  });
});
