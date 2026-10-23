import type { Indexes } from '../data/indexes';
import { createStore, type Store } from './store';
import { formatHash, parseHash, type Route } from './route';

export type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'error'; readonly message: string }
  | { readonly status: 'ready'; readonly ix: Indexes };

export interface AppState {
  readonly load: LoadState;
  readonly route: Route;
  /** Shown once after an invalid link degraded to the overview. */
  readonly notice: string | null;
  readonly theme: 'system' | 'light' | 'dark';
  /** Display pseudonyms instead of names (screenshots, screen sharing). */
  readonly pseudonyms: boolean;
  readonly palette: boolean;
  readonly help: boolean;
}

export function initialState(hash: string): AppState {
  const { route, warning } = parseHash(hash);
  return {
    load: { status: 'loading' },
    route,
    notice: warning,
    theme: 'system',
    pseudonyms: false,
    palette: false,
    help: false,
  };
}

export type AppStore = Store<AppState>;

export function createAppStore(hash: string): AppStore {
  return createStore(initialState(hash));
}

/** Keeps the route and location.hash in sync both ways. Navigation pushes a
 * history entry; camera moves replace it (no entry per pan). Returns an
 * unsubscribe function. */
export function bindLocation(store: AppStore, win: Window = window): () => void {
  const onHash = (): void => {
    const { route, warning } = parseHash(win.location.hash);
    store.set((s) =>
      formatHash(s.route) === formatHash(route) ? s : { ...s, route, notice: warning ?? s.notice },
    );
  };
  win.addEventListener('hashchange', onHash);
  const unsubscribe = store.subscribe(() => {
    const want = formatHash(store.get().route);
    if (win.location.hash !== want && !(want === '#/' && win.location.hash === '')) {
      const current = parseHash(win.location.hash).route;
      const onlyCamera =
        current.view === store.get().route.view &&
        formatHash({ ...current, camera: null }) ===
          formatHash({ ...store.get().route, camera: null });
      if (onlyCamera) {
        win.history.replaceState(null, '', want);
      } else {
        win.history.pushState(null, '', want);
      }
    }
  });
  return () => {
    win.removeEventListener('hashchange', onHash);
    unsubscribe();
  };
}

export function navigate(store: AppStore, route: Route): void {
  store.set((s) => ({ ...s, route, notice: null }));
}
