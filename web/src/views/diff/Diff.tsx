import { useMemo, useRef } from 'react';
import { EdgeStroke } from '../../design/EdgeStroke';
import { Glyph } from '../../design/Glyph';
import type { Tier } from '../../design/tokens';
import { displayName } from '../../shell/names';
import { Empty } from '../../shell/States';
import { formatHash, to } from '../../state/route';
import { Severity } from '../common';
import { exportSVG } from '../export';
import type { ViewProps } from '../registry';
import { diffScene } from './model';

export function Diff({ ix, pseudonyms, update }: ViewProps) {
  const scene = useMemo(() => diffScene(ix), [ix]);
  const svg = useRef<SVGSVGElement>(null);
  const d = ix.analysis.diff;
  if (!scene || !d) {
    return (
      <Empty title="No comparison loaded">
        <p>
          Produce one with{' '}
          <code>escalint diff before.json after.json --format analysis -o diff.json</code> and open
          it.
        </p>
      </Empty>
    );
  }
  const xs = scene.nodes.map((n) => n.x);
  const ys = scene.nodes.map((n) => n.y);
  const pad = 60;
  const minX = Math.min(0, ...xs) - pad;
  const minY = Math.min(0, ...ys) - pad;
  const w = Math.max(...xs, 0) - minX + pad;
  const h = Math.max(...ys, 0) - minY + pad;
  const pos = new Map(scene.nodes.map((n) => [n.node.id, n]));
  const removedFindings = d.removed.objects?.findings ?? [];
  const added = new Set(d.added.findings);
  const addedFindings = ix.analysis.findings.filter((f) => added.has(f.id));
  return (
    <div className="diff">
      <h1 className="view__title">Diff</h1>
      <p className="muted">
        Compared with the analysis of {d.base.collected_at?.slice(0, 10) ?? 'an earlier snapshot'}:
        paths +{d.added.paths.length} −{d.removed.paths.length}, edges +{d.added.edges.length} −
        {d.removed.edges.length}, findings +{d.added.findings.length} −{d.removed.findings.length}.
      </p>
      {scene.edges.length > 0 && (
        <>
          <div className="actions">
            <span className="swatch">
              <span className="diff__key diff__key--added" aria-hidden="true" /> added
            </span>
            <span className="swatch">
              <span className="diff__key diff__key--removed" aria-hidden="true" /> removed (ghost)
            </span>
            <button
              type="button"
              className="button button--ghost"
              onClick={() => {
                if (svg.current) exportSVG(svg.current, 'escalint-diff.svg');
              }}
            >
              Export SVG
            </button>
          </div>
          <div className="trace__canvas">
            <svg
              ref={svg}
              width={w}
              height={h}
              viewBox={`${String(minX)} ${String(minY)} ${String(w)} ${String(h)}`}
              role="img"
              aria-label="Changed edges; the lists below give the same information"
            >
              {scene.edges.map(({ edge, change }) => {
                const a = pos.get(edge.from);
                const b = pos.get(edge.to);
                if (!a || !b) return null;
                return (
                  <g key={edge.id} className={`diff__edge diff__edge--${change}`}>
                    <EdgeStroke
                      kind={edge.kind}
                      d={`M${String(a.x)} ${String(a.y)} L${String(b.x)} ${String(b.y)}`}
                      width={change === 'added' ? 3 : 1.5}
                      conditional={change === 'removed' || edge.status === 'conditional'}
                    />
                  </g>
                );
              })}
              {scene.nodes.map((n) => (
                <g
                  key={n.node.id}
                  className={n.change === 'removed' ? 'diff__node--removed' : undefined}
                >
                  <Glyph
                    kind={n.node.kind}
                    tier={n.node.tier as Tier}
                    radius={9}
                    x={n.x}
                    y={n.y}
                    state={n.change === 'removed' ? 'dimmed' : 'normal'}
                    label={displayName(n.node, pseudonyms)}
                  />
                  <text className="reach__label" x={n.x} y={n.y + 24} textAnchor="middle">
                    {displayName(n.node, pseudonyms)}
                    {n.change !== 'same' ? ` (${n.change})` : ''}
                  </text>
                </g>
              ))}
            </svg>
          </div>
        </>
      )}
      <div className="overview__lists">
        <section aria-labelledby="diff-added">
          <h2 id="diff-added" className="section__title">
            New findings ({addedFindings.length})
          </h2>
          <ul className="rank-list">
            {addedFindings.map((f) => (
              <li key={f.id}>
                <Severity value={f.severity} /> {f.rule_id}{' '}
                <button
                  type="button"
                  className="link-button"
                  onClick={() => {
                    update((r) => ({ ...r, sel: f.id }));
                  }}
                >
                  {f.title}
                </button>
              </li>
            ))}
          </ul>
          <h2 className="section__title">New paths ({scene.addedPaths.length})</h2>
          <ul className="rank-list">
            {scene.addedPaths.map((p) => (
              <li key={p.id}>
                <Severity value={p.severity} />{' '}
                <a href={formatHash(to('path', p.id))}>{p.length} step(s)</a>
              </li>
            ))}
          </ul>
        </section>
        <section aria-labelledby="diff-removed">
          <h2 id="diff-removed" className="section__title">
            Resolved findings ({removedFindings.length})
          </h2>
          <ul className="rank-list">
            {removedFindings.map((f) => (
              <li key={f.id} className="diff__ghost">
                <Severity value={f.severity} /> {f.rule_id} {f.title}
              </li>
            ))}
          </ul>
          <h2 className="section__title">Removed paths ({scene.removedPaths.length})</h2>
          <ul className="rank-list">
            {scene.removedPaths.map((p) => (
              <li key={p.id} className="diff__ghost">
                <Severity value={p.severity} /> {p.length} step(s)
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
