import { lazy, Suspense, useEffect, useState, useSyncExternalStore } from 'react';
import { buildIndexes } from './data/indexes';
import { detectSource, loadAnalysis } from './data/load';
import { ThemeProvider } from './design/theme';
import { applyTheme, resolveTheme } from './design/tokens';
import { Shell } from './shell/Shell';
import { ErrorState, Loading } from './shell/States';
import { bindLocation, type AppStore } from './state/app';
import { useStore } from './state/store';
import type { Analysis } from './contract/analysis';

// The design route exists only in dev and in the public demo build; in the
// embedded/production build this constant is false and the page is dropped.
const designRouteEnabled = import.meta.env.DEV || import.meta.env.VITE_DESIGN_ROUTE === 'true';
const DesignPage = designRouteEnabled
  ? lazy(() => import('./design/DesignPage').then((m) => ({ default: m.DesignPage })))
  : null;

const darkQuery = '(prefers-color-scheme: dark)';

function subscribeDark(onChange: () => void) {
  const media = window.matchMedia(darkQuery);
  media.addEventListener('change', onChange);
  return () => {
    media.removeEventListener('change', onChange);
  };
}

interface Props {
  readonly store: AppStore;
  /** Injectable for tests; defaults to the page's data source. */
  readonly load?: () => Promise<Analysis>;
}

export function App({ store, load }: Props) {
  const prefersDark = useSyncExternalStore(
    subscribeDark,
    () => window.matchMedia(darkQuery).matches,
  );
  const themeChoice = useStore(store, (s) => s.theme);
  const loadState = useStore(store, (s) => s.load);
  // The design page is a separate dev-only page, outside the router.
  const [design] = useState(() => DesignPage !== null && window.location.hash === '#/design');
  const theme = resolveTheme(themeChoice, prefersDark);

  useEffect(() => {
    applyTheme(document.documentElement, theme);
  }, [theme]);

  useEffect(() => (design ? undefined : bindLocation(store)), [store, design]);

  useEffect(() => {
    if (design) return undefined;
    let cancelled = false;
    (load ?? (() => loadAnalysis(detectSource())))().then(
      (a) => {
        if (!cancelled)
          store.set((s) => ({ ...s, load: { status: 'ready', ix: buildIndexes(a) } }));
      },
      (err: unknown) => {
        if (!cancelled)
          store.set((s) => ({
            ...s,
            load: { status: 'error', message: err instanceof Error ? err.message : String(err) },
          }));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [store, load, design]);

  if (DesignPage && design) {
    return (
      <ThemeProvider name={theme}>
        <Suspense fallback={<Loading what="design page" />}>
          <DesignPage
            themeChoice={themeChoice}
            onThemeChoice={(c) => {
              store.set((s) => ({ ...s, theme: c }));
            }}
          />
        </Suspense>
      </ThemeProvider>
    );
  }
  return (
    <ThemeProvider name={theme}>
      {loadState.status === 'loading' && <Loading />}
      {loadState.status === 'error' && <ErrorState message={loadState.message} />}
      {loadState.status === 'ready' && <Shell store={store} ix={loadState.ix} />}
    </ThemeProvider>
  );
}
