import { useMemo, useState } from 'react';
import { displayName } from '../../shell/names';
import { formatHash, to } from '../../state/route';
import { NodeRef, Severity } from '../common';
import type { ViewProps } from '../registry';
import { remainingPaths } from './model';

export function FixPlan({ ix, pseudonyms, update }: ViewProps) {
  const plan = ix.analysis.fix_plan;
  const [applied, setApplied] = useState<ReadonlySet<number>>(() => new Set());
  const left = useMemo(() => remainingPaths(ix, applied), [ix, applied]);
  const total = ix.analysis.paths.length;
  const toggle = (order: number): void => {
    setApplied((s) => {
      const next = new Set(s);
      if (next.has(order)) next.delete(order);
      else next.add(order);
      return next;
    });
  };
  const edgeText = (id: string): string => {
    const e = ix.edges.get(id);
    if (!e) return id;
    const name = (n: string): string => {
      const node = ix.nodes.get(n);
      return node ? displayName(node, pseudonyms) : n;
    };
    return `${name(e.from)} → ${name(e.to)} (${e.kind})`;
  };
  if (plan.length === 0) {
    return (
      <div>
        <h1 className="view__title">Fix plan</h1>
        <p className="muted">No enumerated path reaches Tier 0: nothing to fix.</p>
      </div>
    );
  }
  return (
    <div className="fix">
      <h1 className="view__title">Fix plan</h1>
      <p className="muted">
        {plan.length} change(s) cut all {total} enumerated path(s). The plan is a greedy
        approximation of the smallest set of edges to remove (ADR 0009); re-scan after applying it.
      </p>
      <div className="fix__layout">
        <ol className="fix__steps">
          {plan.map((s) => (
            <li
              key={s.order}
              className={applied.has(s.order) ? 'fix__step fix__step--applied' : 'fix__step'}
            >
              <label className="fix__toggle">
                <input
                  type="checkbox"
                  checked={applied.has(s.order)}
                  onChange={() => {
                    toggle(s.order);
                  }}
                />{' '}
                Preview step {s.order}
              </label>
              <p className="fix__change">{pseudonyms ? edgeText(s.edge_id) : s.change}</p>
              <p className="muted">
                Cuts {s.paths_cut.length} path(s){' · '}
                <button
                  type="button"
                  className="link-button"
                  onClick={() => {
                    update((r) => ({ ...r, sel: s.edge_id }));
                  }}
                >
                  edge details
                </button>
                {!pseudonyms && s.target && <span className="mono"> · {s.target}</span>}
              </p>
            </li>
          ))}
        </ol>
        <section className="fix__preview" aria-labelledby="fix-preview" aria-live="polite">
          <h2 id="fix-preview" className="section__title">
            Preview: {left.length} of {total} path(s) left
          </h2>
          <div className="actions">
            <button
              type="button"
              className="button"
              onClick={() => {
                setApplied(new Set(plan.map((s) => s.order)));
              }}
            >
              Apply all
            </button>
            <button
              type="button"
              className="button button--ghost"
              onClick={() => {
                setApplied(new Set());
              }}
            >
              Reset
            </button>
          </div>
          {left.length === 0 ? (
            <p>Every enumerated path is cut.</p>
          ) : (
            <ul className="rank-list">
              {left.slice(0, 50).map((p) => (
                <li key={p.id}>
                  <Severity value={p.severity} />{' '}
                  <NodeRef ix={ix} id={p.source} pseudonyms={pseudonyms} />{' '}
                  <a href={formatHash(to('path', p.id))}>{p.length} step(s)</a>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
