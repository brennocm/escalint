import { describe, expect, it } from 'vitest';
import { applyTheme, cssVarName, cssVariables, resolveTheme, themes } from './tokens';

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
      expect(vars).toHaveLength(Object.keys(themes[theme]).length);
      const names = vars.map(([name]) => name);
      expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
    }
  });
});

describe('applyTheme', () => {
  it('writes custom properties and the data-theme attribute', () => {
    const el = document.createElement('div');
    applyTheme(el, 'dark');
    expect(el.style.getPropertyValue('--color-bg')).toBe(themes.dark.bg);
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
