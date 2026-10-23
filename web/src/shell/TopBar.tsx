import type { AppState } from '../state/app';
import { formatHash, to, type View } from '../state/route';
import { viewTitles } from './candidates';

interface Props {
  readonly state: AppState;
  readonly hasDiff: boolean;
  readonly onSearch: () => void;
  readonly onTheme: () => void;
  readonly onPseudonyms: () => void;
  readonly onHelp: () => void;
}

const navViews: readonly View[] = ['overview', 'atlas', 'findings', 'exposure', 'fix', 'detect'];

export function TopBar({ state, hasDiff, onSearch, onTheme, onPseudonyms, onHelp }: Props) {
  const current = state.route.view;
  const views = hasDiff ? [...navViews, 'diff' as const] : navViews;
  return (
    <header className="topbar">
      <a className="topbar__brand" href="#/">
        escalint
      </a>
      <nav className="topbar__nav" aria-label="Views">
        {views.map((v) => (
          <a
            key={v}
            href={formatHash(to(v))}
            className="topbar__link"
            aria-current={current === v ? 'page' : undefined}
          >
            {viewTitles[v]}
          </a>
        ))}
      </nav>
      <div className="topbar__tools">
        <button
          type="button"
          className="button topbar__search"
          onClick={onSearch}
          aria-keyshortcuts="Control+K Meta+K"
        >
          Search <kbd>Ctrl K</kbd>
        </button>
        <button
          type="button"
          className="button button--ghost"
          onClick={onTheme}
          aria-label={`Theme: ${state.theme}`}
        >
          Theme: {state.theme}
        </button>
        <button
          type="button"
          className="button button--ghost"
          aria-pressed={state.pseudonyms}
          onClick={onPseudonyms}
        >
          Pseudonyms
        </button>
        <button
          type="button"
          className="button button--ghost"
          onClick={onHelp}
          aria-label="Keyboard shortcuts"
          aria-keyshortcuts="?"
        >
          ?
        </button>
      </div>
    </header>
  );
}
