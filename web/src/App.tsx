import { lazy, Suspense, useEffect, useState, useSyncExternalStore } from 'react';
import { ThemeProvider } from './design/theme';
import { applyTheme, resolveTheme, type ThemeName } from './design/tokens';

// The design route exists only in dev and in the public demo build; in the
// embedded/production build this constant is false and the page is dropped.
const designRouteEnabled = import.meta.env.DEV || import.meta.env.VITE_DESIGN_ROUTE === 'true';
// The import() sits behind the constant so the bundler drops the chunk entirely.
const DesignPage = designRouteEnabled
  ? lazy(() => import('./design/DesignPage').then((m) => ({ default: m.DesignPage })))
  : null;

const darkQuery = '(prefers-color-scheme: dark)';

function subscribeHash(onChange: () => void) {
  window.addEventListener('hashchange', onChange);
  return () => {
    window.removeEventListener('hashchange', onChange);
  };
}

function subscribeDark(onChange: () => void) {
  const media = window.matchMedia(darkQuery);
  media.addEventListener('change', onChange);
  return () => {
    media.removeEventListener('change', onChange);
  };
}

export function App() {
  const hash = useSyncExternalStore(subscribeHash, () => window.location.hash);
  const prefersDark = useSyncExternalStore(
    subscribeDark,
    () => window.matchMedia(darkQuery).matches,
  );
  const [themeChoice, setThemeChoice] = useState<ThemeName | 'system'>('system');
  const theme = resolveTheme(themeChoice, prefersDark);

  useEffect(() => {
    applyTheme(document.documentElement, theme);
  }, [theme]);

  return (
    <ThemeProvider name={theme}>
      {DesignPage && hash === '#/design' ? (
        <Suspense fallback={<p className="loading">Loading…</p>}>
          <DesignPage themeChoice={themeChoice} onThemeChoice={setThemeChoice} />
        </Suspense>
      ) : (
        <main className="app">
          <h1 className="app__title">escalint</h1>
          <p className="app__subtitle">Who can reach what in your AWS IAM.</p>
        </main>
      )}
    </ThemeProvider>
  );
}
