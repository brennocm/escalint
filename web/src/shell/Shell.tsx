import { Suspense, useEffect, useMemo, useRef } from 'react';
import type { Indexes } from '../data/indexes';
import { type AppStore, navigate } from '../state/app';
import { to, type Route } from '../state/route';
import { useStore } from '../state/store';
import { viewComponents } from '../views/registry';
import { candidates, routeFor } from './candidates';
import { CommandPalette } from './CommandPalette';
import { DemoBanner } from './DemoBanner';
import { DetailsPanel } from './DetailsPanel';
import { HelpDialog } from './HelpDialog';
import { keyAction } from './keys';
import { Legend } from './Legend';
import { displayName } from './names';
import { Loading } from './States';
import { TopBar } from './TopBar';

const nextTheme = { system: 'light', light: 'dark', dark: 'system' } as const;

export function Shell({ store, ix }: { readonly store: AppStore; readonly ix: Indexes }) {
  const state = useStore(store, (s) => s);
  const { route, pseudonyms } = state;
  const pending = useRef('');
  const list = useMemo(() => candidates(ix, pseudonyms), [ix, pseudonyms]);

  const go = (r: Route): void => {
    navigate(store, r);
  };
  const update = (patch: (r: Route) => Route): void => {
    store.set((s) => ({ ...s, route: patch(s.route) }));
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      const t = e.target as HTMLElement | null;
      const inField =
        !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
      const { action, pending: p } = keyAction(e, inField, pending.current);
      pending.current = p;
      if (!action) return;
      e.preventDefault();
      switch (action.type) {
        case 'palette':
          store.set((s) => ({ ...s, palette: true }));
          break;
        case 'help':
          store.set((s) => ({ ...s, help: true }));
          break;
        case 'theme':
          store.set((s) => ({ ...s, theme: nextTheme[s.theme] }));
          break;
        case 'pseudonyms':
          store.set((s) => ({ ...s, pseudonyms: !s.pseudonyms }));
          break;
        case 'escape':
          store.set((s) =>
            s.palette || s.help
              ? { ...s, palette: false, help: false }
              : { ...s, route: { ...s.route, sel: null } },
          );
          break;
        case 'go':
          navigate(store, to(action.view));
          break;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, [store]);

  const View = viewComponents[route.view];
  const selected = route.sel ? ix.nodes.get(route.sel) : undefined;
  const announcement = route.sel
    ? `Selected ${selected ? displayName(selected, pseudonyms) : route.sel}`
    : '';

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <TopBar
        state={state}
        hasDiff={!!ix.analysis.diff}
        onSearch={() => {
          store.set((s) => ({ ...s, palette: true }));
        }}
        onTheme={() => {
          store.set((s) => ({ ...s, theme: nextTheme[s.theme] }));
        }}
        onPseudonyms={() => {
          store.set((s) => ({ ...s, pseudonyms: !s.pseudonyms }));
        }}
        onHelp={() => {
          store.set((s) => ({ ...s, help: true }));
        }}
      />
      {import.meta.env.VITE_DEMO === 'true' && <DemoBanner />}
      {state.notice && (
        <div className="notice" role="status">
          {state.notice}
          <button
            type="button"
            className="button button--ghost"
            onClick={() => {
              store.set((s) => ({ ...s, notice: null }));
            }}
          >
            Dismiss
          </button>
        </div>
      )}
      {ix.analysis.snapshot.redacted && (
        <div className="notice notice--info" role="note">
          Identifiers in this analysis are redacted: names and IDs are per-run pseudonyms.
        </div>
      )}
      <div className="shell__body">
        <main id="main" className="shell__main" tabIndex={-1}>
          <Suspense fallback={<Loading what="view" />}>
            <View ix={ix} route={route} pseudonyms={pseudonyms} navigate={go} update={update} />
          </Suspense>
        </main>
        {route.sel && (
          <DetailsPanel
            ix={ix}
            sel={route.sel}
            pseudonyms={pseudonyms}
            onNavigate={go}
            onClose={() => {
              update((r) => ({ ...r, sel: null }));
            }}
          />
        )}
      </div>
      <Legend />
      <div className="visually-hidden" aria-live="polite">
        {announcement}
      </div>
      {state.palette && (
        <CommandPalette
          candidates={list}
          onClose={() => {
            store.set((s) => ({ ...s, palette: false }));
          }}
          onChoose={(c) => {
            store.set((s) => ({ ...s, palette: false }));
            go(routeFor(c));
          }}
        />
      )}
      {state.help && (
        <HelpDialog
          onClose={() => {
            store.set((s) => ({ ...s, help: false }));
          }}
        />
      )}
    </div>
  );
}
