import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { hardened, vulnerable } from '../../data/fixtures';
import { ThemeProvider } from '../../design/theme';
import { to } from '../../state/route';
import { FixPlan } from './FixPlan';
import { firstSteps, remainingPaths } from './model';

const ix = buildIndexes(vulnerable);

describe('fix plan preview', () => {
  it('matches the engine: each step cuts exactly its paths', () => {
    const plan = vulnerable.fix_plan;
    let left = vulnerable.paths.length;
    for (let n = 1; n <= plan.length; n++) {
      left -= plan[n - 1]?.paths_cut.length ?? 0;
      expect(remainingPaths(ix, firstSteps(n)).length).toBe(left);
    }
    expect(remainingPaths(ix, firstSteps(plan.length))).toEqual([]);
    expect(remainingPaths(ix, new Set()).length).toBe(vulnerable.paths.length);
  });
});

describe('FixPlan view', () => {
  const view = (a = ix, pseudonyms = false) =>
    render(
      <ThemeProvider name="light">
        <FixPlan
          ix={a}
          route={to('fix')}
          pseudonyms={pseudonyms}
          navigate={() => undefined}
          update={() => undefined}
        />
      </ThemeProvider>,
    );
  it('previews steps', () => {
    view();
    expect(screen.getByRole('heading', { name: /Preview: \d+ of \d+/ }).textContent).toContain(
      `${String(vulnerable.paths.length)} of`,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Apply all' }));
    expect(screen.getByText('Every enumerated path is cut.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Reset' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Preview step 1' }));
    expect(screen.getByRole('heading', { name: /Preview/ }).textContent).not.toContain(
      `${String(vulnerable.paths.length)} of`,
    );
  });
  it('handles empty plans and pseudonyms', () => {
    const { unmount } = view(buildIndexes({ ...hardened, fix_plan: [] }));
    expect(screen.getByText(/nothing to fix/)).toBeTruthy();
    unmount();
    view(ix, true);
    expect(screen.queryByText(/inline:arn/)).toBeNull();
  });
});
