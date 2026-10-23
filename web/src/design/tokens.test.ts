import { describe, expect, it } from 'vitest';
import {
  applyTheme,
  capabilityLevels,
  detectionStates,
  cssVarName,
  cssVariables,
  escalationEdgeKinds,
  nodeRadius,
  resolveTheme,
  severities,
  themes,
  tierRingWidth,
  tiers,
} from './tokens';

describe('cssVarName', () => {
  it.each([
    ['bg', '--color-bg'],
    ['textMuted', '--color-text-muted'],
  ])('%s -> %s', (token, want) => {
    expect(cssVarName(token)).toBe(want);
  });
});

describe('cssVariables', () => {
  it('covers every token of both themes in sorted order', () => {
    for (const theme of ['light', 'dark'] as const) {
      const vars = cssVariables(theme);
      expect(vars).toHaveLength(
        Object.keys(themes[theme].colors).length +
          tiers.length +
          escalationEdgeKinds.length +
          severities.length +
          capabilityLevels.length +
          detectionStates.length,
      );
      expect(vars).toContainEqual([
        '--edge-modify-permissions',
        themes[theme].edge.modify_permissions,
      ]);
      expect(vars).toContainEqual(['--tier-0', themes[theme].tier[0]]);
      const names = vars.map(([name]) => name);
      expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
    }
  });
});

describe('applyTheme', () => {
  it('writes custom properties and the data-theme attribute', () => {
    const el = document.createElement('div');
    applyTheme(el, 'dark');
    expect(el.style.getPropertyValue('--color-bg')).toBe(themes.dark.colors.bg);
    expect(el.dataset.theme).toBe('dark');
  });
});

describe('resolveTheme', () => {
  it.each([
    ['system', true, 'dark'],
    ['system', false, 'light'],
    ['light', true, 'light'],
    ['dark', false, 'dark'],
  ] as const)('choice=%s prefersDark=%s -> %s', (choice, prefersDark, want) => {
    expect(resolveTheme(choice, prefersDark)).toBe(want);
  });
});

describe('nodeRadius', () => {
  it.each([
    [0, 100, 4],
    [100, 100, 18],
    [25, 100, 11],
    [500, 100, 18],
    [5, 0, 4],
  ])('reachable=%d max=%d -> %d px', (reachable, max, want) => {
    expect(nodeRadius(reachable, max)).toBeCloseTo(want, 6);
  });
});

describe('tierRingWidth', () => {
  it('makes Tier 0 thicker than the others', () => {
    for (const tier of [1, 2, 3] as const) {
      expect(tierRingWidth(0)).toBeGreaterThan(tierRingWidth(tier));
    }
  });
});
