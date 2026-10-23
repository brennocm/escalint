import { useState } from 'react';
import { EdgeStroke } from '../design/EdgeStroke';
import { Glyph } from '../design/Glyph';
import {
  edgeLabels,
  escalationEdgeKinds,
  nodeKinds,
  nodeLabels,
  tiers,
  type Tier,
} from '../design/tokens';

const tierText: Record<Tier, string> = {
  0: 'Tier 0: effective administrator',
  1: 'Tier 1: has a path to Tier 0',
  2: 'Tier 2: sensitive access, no path',
  3: 'Tier 3: everything else',
};

/** Always-visible, collapsible legend: glyph = kind, ring = tier, stroke
 * pattern and color = edge kind. Nothing relies on color alone. */
export function Legend() {
  // Collapsed by default so it never hides the view; one click opens it.
  const [open, setOpen] = useState(false);
  return (
    <aside className="legend" aria-label="Legend">
      <button
        type="button"
        className="legend__toggle"
        aria-expanded={open}
        onClick={() => {
          setOpen(!open);
        }}
      >
        Legend
      </button>
      {open && (
        <div className="legend__body">
          <ul className="legend__list">
            {nodeKinds.map((k) => (
              <li key={k}>
                <svg width="20" height="20" viewBox="-10 -10 20 20" aria-hidden="true">
                  <Glyph kind={k} tier={3} radius={6} />
                </svg>
                {nodeLabels[k]}
              </li>
            ))}
          </ul>
          <ul className="legend__list">
            {tiers.map((t) => (
              <li key={t}>
                <svg width="20" height="20" viewBox="-10 -10 20 20" aria-hidden="true">
                  <Glyph kind="role" tier={t} radius={5} />
                </svg>
                {tierText[t]}
              </li>
            ))}
          </ul>
          <ul className="legend__list">
            {escalationEdgeKinds.map((k) => (
              <li key={k}>
                <svg width="36" height="12" viewBox="0 0 36 12" aria-hidden="true">
                  <EdgeStroke kind={k} d="M2 6 L30 6" />
                </svg>
                {edgeLabels[k]}
              </li>
            ))}
            <li>
              <svg width="36" height="12" viewBox="0 0 36 12" aria-hidden="true">
                <EdgeStroke kind="assume" d="M2 6 L30 6" conditional />
              </svg>
              Conditional (a condition or prerequisite was not verified)
            </li>
          </ul>
        </div>
      )}
    </aside>
  );
}
