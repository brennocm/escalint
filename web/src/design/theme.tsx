import { createContext, useContext, type ReactNode } from 'react';
import { themes, type Theme, type ThemeName } from './tokens';

const ThemeContext = createContext<ThemeName>('light');

export function ThemeProvider({ name, children }: { name: ThemeName; children: ReactNode }) {
  return <ThemeContext.Provider value={name}>{children}</ThemeContext.Provider>;
}

/** Resolved token values for components that draw SVG. Colors are passed as
 * attributes (not CSS variables) so exported SVG files are self-contained. */
export function useTheme(): Theme {
  return themes[useContext(ThemeContext)];
}

export function useThemeName(): ThemeName {
  return useContext(ThemeContext);
}
