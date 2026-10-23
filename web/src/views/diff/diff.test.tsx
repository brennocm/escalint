import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { Analysis } from '../../contract/analysis';
import { buildIndexes } from '../../data/indexes';
import { diffed, vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { to } from '../../state/route';
import { Diff } from './Diff';
import { diffScene } from './model';

function withRemoval(a: Analysis): Analysis {
  const d = a.diff;
  if (!d) throw new Error('fixture has no diff');
  const ghost = vulnerable.edges[0];
  const ghostFinding = vulnerable.findings[0];
  const ghostPath = vulnerable.paths[0];
  if (!ghost || !ghostFinding || !ghostPath) throw new Error('fixture');
  const nodes = vulnerable.nodes.filter((n) => n.id === ghost.from || n.id === ghost.to);
  return {
    ...a,
    diff: {
      ...d,
      removed: {
        edges: [ghost.id],
        paths: [ghostPath.id],
        findings: [ghostFinding.id],
        nodes: nodes.map((n) => n.id),
        objects: { nodes, edges: [ghost], paths: [ghostPath], findings: [ghostFinding] },
      },
    },
  };
}

describe('diff scene', () => {
  it('lays out the changed edges deterministically', () => {
    const ix = buildIndexes(diffed);
    const s = diffScene(ix);
    expect(s?.edges.every((e) => e.change === 'added')).toBe(true);
    expect(s?.addedPaths.length).toBe(diffed.diff?.added.paths.length);
    expect(diffScene(ix)).toEqual(s);
    expect(diffScene(buildIndexes(vulnerable))).toBeNull();
  });
  it('keeps removed objects as ghosts', () => {
    const s = diffScene(buildIndexes(withRemoval(diffed)));
    expect(s?.edges.some((e) => e.change === 'removed')).toBe(true);
    expect(s?.nodes.some((n) => n.change === 'removed')).toBe(true);
    expect(s?.removedPaths).toHaveLength(1);
  });
});

describe('Diff view', () => {
  it('lists changes and draws them', () => {
    render(
      <ThemeProvider name="light">
        <Diff
          ix={buildIndexes(withRemoval(diffed))}
          route={to('diff')}
          pseudonyms={false}
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('img', { name: /Changed edges/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /New findings \(\d+\)/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Resolved findings (1)' })).toBeTruthy();
  });
  it('explains how to produce a diff', () => {
    render(
      <ThemeProvider name="dark">
        <Diff
          ix={buildIndexes(vulnerable)}
          route={to('diff')}
          pseudonyms
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
    expect(screen.getByRole('heading', { name: 'No comparison loaded' })).toBeTruthy();
  });
});
