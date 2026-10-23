import { useMemo, useRef, type KeyboardEvent } from 'react';
import { DetectionIndicator } from '../../design/DetectionIndicator';
import { EdgeStroke } from '../../design/EdgeStroke';
import { Glyph } from '../../design/Glyph';
import type { Tier } from '../../design/tokens';
import { PolicyExplainer } from '../../explainer/PolicyExplainer';
import { displayAccount, displayName } from '../../shell/names';
import { Empty } from '../../shell/States';
import { formatHash, to } from '../../state/route';
import { Severity } from '../common';
import { exportPNG, exportSVG } from '../export';
import type { ViewProps } from '../registry';
import { card, chokeWidth, neighbor, traceLayout, type CardBox } from './layout';

export function Trace({ ix, route, pseudonyms, update }: ViewProps) {
  const path = route.id ? ix.paths.get(route.id) : undefined;
  const layout = useMemo(() => (path ? traceLayout(ix, path) : null), [ix, path]);
  const svg = useRef<SVGSVGElement>(null);
  if (!path || !layout) {
    return (
      <Empty title="Path not found">
        <p>
          This path is not in the analysis. Pick one from the{' '}
          <a href={formatHash(to('findings'))}>findings</a>.
        </p>
      </Empty>
    );
  }
  const selectedEdge = route.sel ? ix.edges.get(route.sel) : undefined;
  const focusCard = (c: CardBox | undefined): void => {
    if (!c) return;
    svg.current
      ?.querySelector<SVGGElement>(`[data-card="${String(c.row)}-${String(c.col)}"]`)
      ?.focus();
  };
  const onCardKey = (c: CardBox) => (e: KeyboardEvent<SVGGElement>) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      update((r) => ({ ...r, sel: c.id }));
      return;
    }
    const next = neighbor(layout, c, e.key);
    if (next) {
      e.preventDefault();
      focusCard(next);
    }
  };
  const source = ix.nodes.get(path.source);
  return (
    <div className="trace">
      <h1 className="view__title">
        Trace <Severity value={path.severity} />
      </h1>
      <p className="muted">
        {source ? displayName(source, pseudonyms) : path.source} reaches Tier 0 in {path.length}{' '}
        step(s)
        {path.status === 'conditional' ? ' if the unverified conditions hold' : ''}.{' '}
        {layout.rows.length > 1 &&
          `${String(layout.rows.length - 1)} alternative path(s) from the same principal below.`}
      </p>
      <div className="actions">
        <button
          type="button"
          className="button"
          onClick={() => {
            if (svg.current) exportSVG(svg.current, 'escalint-trace.svg');
          }}
        >
          Export SVG
        </button>
        <button
          type="button"
          className="button"
          onClick={() => {
            if (svg.current) void exportPNG(svg.current, 'escalint-trace.png');
          }}
        >
          Export PNG
        </button>
      </div>
      <div className="trace__canvas">
        <svg
          ref={svg}
          className="trace__svg"
          width={layout.width}
          height={layout.height}
          viewBox={`0 0 ${String(layout.width)} ${String(layout.height)}`}
          role="group"
          aria-label="Escalation path diagram"
        >
          {layout.edges.map((e) => {
            const edge = ix.edges.get(e.id);
            if (!edge) return null;
            const choke = ix.chokeByEdge.get(e.id);
            const selected = route.sel === e.id;
            const midX = (e.x1 + e.x2) / 2;
            return (
              <g
                key={`${String(e.row)}-${e.id}`}
                className={selected ? 'trace__edge trace__edge--selected' : 'trace__edge'}
              >
                <EdgeStroke
                  kind={edge.kind}
                  d={`M${String(e.x1)} ${String(e.y1)} L${String(e.x2 - 6)} ${String(e.y2)}`}
                  width={chokeWidth(choke?.paths_cut ?? 1)}
                  conditional={edge.status === 'conditional'}
                  flow={e.row === 0}
                />
                <DetectionIndicator
                  state={edge.detection.visibility}
                  x={midX}
                  y={e.y1 - 14}
                  size={9}
                />
                <rect
                  className="trace__hit"
                  x={e.x1}
                  y={e.y1 - 22}
                  width={e.x2 - e.x1}
                  height={44}
                  tabIndex={0}
                  role="button"
                  aria-label={`${edge.kind} edge: ${edge.required_actions.join(', ')}. Open the policy explainer.`}
                  onClick={() => {
                    update((r) => ({ ...r, sel: e.id }));
                  }}
                  onKeyDown={(ev) => {
                    if (ev.key === 'Enter' || ev.key === ' ') {
                      ev.preventDefault();
                      update((r) => ({ ...r, sel: e.id }));
                    }
                  }}
                />
                <text className="trace__label" x={midX} y={e.y1 + 18} textAnchor="middle">
                  {edge.kind}
                  {choke && choke.paths_cut > 1 ? ` · choke ×${String(choke.paths_cut)}` : ''}
                </text>
              </g>
            );
          })}
          {layout.cards.map((c) => {
            const n = ix.nodes.get(c.id);
            if (!n) return null;
            const name = displayName(n, pseudonyms);
            return (
              <g
                key={`${String(c.row)}-${String(c.col)}`}
                data-card={`${String(c.row)}-${String(c.col)}`}
                className={route.sel === c.id ? 'trace__card trace__card--selected' : 'trace__card'}
                transform={`translate(${String(c.x)} ${String(c.y)})`}
                tabIndex={0}
                role="button"
                aria-label={`${n.kind} ${name}, tier ${String(n.tier)}${c.row === 0 ? '' : ', alternative path'}`}
                onClick={() => {
                  update((r) => ({ ...r, sel: c.id }));
                }}
                onKeyDown={onCardKey(c)}
              >
                <rect className="trace__box" width={card.width} height={card.height} rx={10} />
                <Glyph
                  kind={n.kind}
                  tier={n.tier as Tier}
                  radius={10}
                  x={26}
                  y={card.height / 2}
                  stale={n.flags.includes('stale')}
                  conditional={n.tier_conditional}
                  label={name}
                />
                <text className="trace__name" x={48} y={26}>
                  {name.length > 22 ? `${name.slice(0, 21)}…` : name}
                </text>
                <text className="trace__meta" x={48} y={46}>
                  tier {n.tier}
                  {n.account ? ` · ${displayAccount(n.account, pseudonyms)}` : ''}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <section aria-labelledby="trace-steps">
        <h2 id="trace-steps" className="section__title">
          Steps
        </h2>
        <table className="table">
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">From</th>
              <th scope="col">Edge</th>
              <th scope="col">To</th>
              <th scope="col">Required actions</th>
              <th scope="col">pathfinding.cloud</th>
              <th scope="col">CloudTrail</th>
            </tr>
          </thead>
          <tbody>
            {path.edges.map((id, i) => {
              const e = ix.edges.get(id);
              if (!e) return null;
              const from = ix.nodes.get(e.from);
              const toNode = ix.nodes.get(e.to);
              return (
                <tr
                  key={id}
                  aria-selected={route.sel === id}
                  className={route.sel === id ? 'row--selected' : undefined}
                >
                  <td>{i + 1}</td>
                  <td>{from ? displayName(from, pseudonyms) : e.from}</td>
                  <td>
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => {
                        update((r) => ({ ...r, sel: id }));
                      }}
                    >
                      {e.kind}
                      {e.status === 'conditional' ? ' (conditional)' : ''}
                    </button>
                  </td>
                  <td>{toNode ? displayName(toNode, pseudonyms) : e.to}</td>
                  <td className="mono">{e.required_actions.join(', ')}</td>
                  <td>
                    {e.pathfinding_ids.map((p) => (
                      <a
                        key={p}
                        href={`https://pathfinding.cloud/paths/aws/${encodeURIComponent(p)}`}
                        rel="noreferrer noopener"
                        target="_blank"
                      >
                        {p}{' '}
                      </a>
                    ))}
                  </td>
                  <td>
                    {e.detection.visibility}
                    {e.detection.events.length
                      ? `: ${e.detection.events.map((ev) => ev.name).join(', ')}`
                      : ''}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
      {selectedEdge && <PolicyExplainer ix={ix} edge={selectedEdge} pseudonyms={pseudonyms} />}
    </div>
  );
}
