// Design tokens: the single source of every color, size and duration in the UI.
// Components never use literal colors; they read the CSS custom properties that
// applyTheme() derives from these objects. The full palette arrives in Phase 1D.

export type ThemeName = 'light' | 'dark';

export interface ColorTokens {
  bg: string;
  surface: string;
  text: string;
  textMuted: string;
  accent: string;
  border: string;
}

export const themes: Record<ThemeName, ColorTokens> = {
  light: {
    bg: '#f7f7f8',
    surface: '#ffffff',
    text: '#17181c',
    textMuted: '#5b5e69',
    accent: '#3d5afe',
    border: '#d9dbe1',
  },
  dark: {
    bg: '#101114',
    surface: '#181a1f',
    text: '#eceef2',
    textMuted: '#a3a7b3',
    accent: '#8c9eff',
    border: '#2c2f37',
  },
};

export const typography = {
  fontSans: 'Inter, system-ui, sans-serif',
  fontMono: '"JetBrains Mono", ui-monospace, monospace',
} as const;

/** Converts a camelCase token name into its CSS custom property name. */
export function cssVarName(token: string): string {
  return `--color-${token.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`;
}

/** Returns the CSS custom properties for a theme, sorted for determinism. */
export function cssVariables(theme: ThemeName): [string, string][] {
  const colors = themes[theme];
  const names = Object.keys(colors) as (keyof ColorTokens)[];
  return names
    .map((name): [string, string] => [cssVarName(name), colors[name]])
    .sort(([a], [b]) => a.localeCompare(b));
}

/** Writes the theme onto an element (normally <html>) via the CSSOM, which the
 * strict CSP allows, unlike inline style attributes in markup. */
export function applyTheme(root: HTMLElement, theme: ThemeName): void {
  for (const [name, value] of cssVariables(theme)) {
    root.style.setProperty(name, value);
  }
  root.style.setProperty('--font-sans', typography.fontSans);
  root.style.setProperty('--font-mono', typography.fontMono);
  root.dataset.theme = theme;
}

/** Picks the theme from an explicit choice or the OS preference. */
export function resolveTheme(choice: ThemeName | 'system', prefersDark: boolean): ThemeName {
  if (choice === 'system') {
    return prefersDark ? 'dark' : 'light';
  }
  return choice;
}
