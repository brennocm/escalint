import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { search, type Candidate, type Match } from '../search/fuzzy';

interface Props {
  readonly candidates: readonly Candidate[];
  readonly onChoose: (c: Candidate) => void;
  readonly onClose: () => void;
}

function Highlighted({ text, positions }: { text: string; positions: readonly number[] }) {
  const set = new Set(positions);
  return (
    <>
      {Array.from(text).map((ch, i) =>
        set.has(i) ? (
          <mark key={i} className="palette__hit">
            {ch}
          </mark>
        ) : (
          <span key={i}>{ch}</span>
        ),
      )}
    </>
  );
}

/** Ctrl/⌘+K: fuzzy search over views, principals, rules, techniques and
 * paths. Keyboard: arrows move, Enter chooses, Escape closes. */
export function CommandPalette({ candidates, onChoose, onClose }: Props) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  const matches: Match[] = useMemo(() => search(query, candidates, 30), [query, candidates]);

  useEffect(() => {
    input.current?.focus();
  }, []);

  const onKey = (e: KeyboardEvent<HTMLInputElement>): void => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, Math.max(matches.length - 1, 0)));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter') {
      const m = matches[active];
      if (m) {
        e.preventDefault();
        onChoose(m.candidate);
      }
    }
  };

  return (
    <div
      className="overlay"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search">
        <input
          ref={input}
          className="palette__input"
          type="search"
          role="combobox"
          aria-label="Search"
          aria-expanded={matches.length > 0}
          aria-controls={listId}
          aria-activedescendant={matches[active] ? `${listId}-${String(active)}` : undefined}
          aria-autocomplete="list"
          onKeyDown={onKey}
          placeholder="Search principals, ARNs, rules, ATT&CK techniques, paths…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
        />
        <div id={listId} className="palette__list" role="listbox" aria-label="Results">
          {matches.map((m, i) => (
            <div
              key={m.candidate.key}
              id={`${listId}-${String(i)}`}
              role="option"
              aria-selected={i === active}
              className={i === active ? 'palette__item palette__item--active' : 'palette__item'}
              onMouseEnter={() => {
                setActive(i);
              }}
              onClick={() => {
                onChoose(m.candidate);
              }}
              onKeyDown={() => undefined}
              tabIndex={-1}
            >
              <span className="palette__label">
                <Highlighted
                  text={m.candidate.label}
                  positions={m.candidate.text.startsWith(m.candidate.label) ? m.positions : []}
                />
              </span>
              <span className="palette__detail">{m.candidate.detail}</span>
            </div>
          ))}
          {query.trim() !== '' && matches.length === 0 && (
            <p className="palette__empty">No match.</p>
          )}
        </div>
      </div>
    </div>
  );
}
