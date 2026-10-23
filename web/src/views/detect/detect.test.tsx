import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { hardened, vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { to } from '../../state/route';
import { Detect } from './Detect';
import { detectionRows, eventCounts } from './model';

const ix = buildIndexes(vulnerable);

describe('detection model', () => {
  it('lists every path step, worst paths first', () => {
    const rows = detectionRows(ix);
    expect(rows.length).toBe(vulnerable.paths.reduce((s, p) => s + p.edges.length, 0));
    expect(rows[0]?.path.severity).toBe('critical');
    expect(detectionRows(ix, 3)).toHaveLength(3);
  });
  it('counts events once per edge', () => {
    const counts = eventCounts(detectionRows(ix));
    expect(counts.length).toBeGreaterThan(0);
    expect([...counts].sort((a, b) => b.steps - a.steps)).toEqual(counts);
    expect(counts.some((c) => c.source === 'iam.amazonaws.com')).toBe(true);
  });
});

describe('Detect view', () => {
  it('shows events, techniques and steps', () => {
    render(
      <ThemeProvider name="light">
        <Detect
          ix={ix}
          route={to('detect')}
          pseudonyms={false}
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('heading', { name: 'Events to alert on' })).toBeTruthy();
    expect(screen.getAllByRole('link', { name: /T1098\.003/ }).length).toBeGreaterThan(0);
  });
  it('handles analyses without paths', () => {
    render(
      <ThemeProvider name="dark">
        <Detect
          ix={buildIndexes({
            ...hardened,
            paths: [],
            attack: { ...hardened.attack, techniques: [] },
          })}
          route={to('detect')}
          pseudonyms
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByText('No path steps.')).toBeTruthy();
  });
});
