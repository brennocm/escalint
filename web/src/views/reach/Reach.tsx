import { useMemo, useRef, type KeyboardEvent } from 'react';
import { EdgeStroke } from '../../design/EdgeStroke';
import { Glyph } from '../../design/Glyph';
import { nodeRadius, type Tier } from '../../design/tokens';
import { displayName } from '../../shell/names';
import { Empty } from '../../shell/States';
import { to } from '../../state/route';
import { exportPNG, exportSVG } from '../export';
import type { ViewProps } from '../registry';
import { reachLayout, ringGap, type RingNode } from './layout';

export function Reach({ ix, route, pseudonyms, navigate, update }: ViewProps) {
  const center = route.id ? ix.nodes.get(route.id) : undefined;
  const layout = useMemo(
    () => (center ? reachLayout(ix, center.id, route.dir) : null),
    [ix, center, route.dir],
  );
  const svg = useRef<SVGSVGElement>(null);
  if (!center || !layout) {
    return <Empty title="Principal not found">This node is not in the analysis.</Empty>;
  }
  const pos = new Map(layout.nodes.map((n) => [n.id, n]));
  const size = (layout.radius + 60) * 2;
  const labels = layout.nodes.length <= 40;
  const move = (n: RingNode, key: string): RingNode | undefined => {
    const ring = layout.rings[n.ring] ?? [];
    const i = ring.indexOf(n.id);
    let id: string | undefined;
    if (key === 'ArrowRight') id = ring[(i + 1) % ring.length];
    if (key === 'ArrowLeft') id = ring[(i - 1 + ring.length) % ring.length];
    if (key === 'ArrowDown') id = layout.rings[n.ring + 1]?.[0];
    if (key === 'ArrowUp') id = layout.rings[n.ring - 1]?.[0];
    return id ? pos.get(id) : undefined;
  };
  const onKey = (n: RingNode) => (e: KeyboardEvent<SVGGElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      navigate({ ...to('reach', n.id), dir: route.dir, sel: n.id });
      return;
    }
    if (e.key === ' ') {
      e.preventDefault();
      update((r) => ({ ...r, sel: n.id }));
      return;
    }
    const next = move(n, e.key);
    if (next) {
      e.preventDefault();
      svg.current?.querySelector<SVGGElement>(`[data-node="${next.id}"]`)?.focus();
    }
  };
  const name = displayName(center, pseudonyms);
  return (
    <div className="reach">
      <h1 className="view__title">Reach: {name}</h1>
      <div className="actions" role="group" aria-label="Direction">
        <button
          type="button"
          className="button"
          aria-pressed={route.dir === 'out'}
          onClick={() => {
            update((r) => ({ ...r, dir: 'out' }));
          }}
        >
          Where it can go
        </button>
        <button
          type="button"
          className="button"
          aria-pressed={route.dir === 'in'}
          onClick={() => {
            update((r) => ({ ...r, dir: 'in' }));
          }}
        >
          Who can reach it
        </button>
        <button
          type="button"
          className="button button--ghost"
          onClick={() => {
            if (svg.current) exportSVG(svg.current, 'escalint-reach.svg');
          }}
        >
          Export SVG
        </button>
        <button
          type="button"
          className="button button--ghost"
          onClick={() => {
            if (svg.current) void exportPNG(svg.current, 'escalint-reach.png');
          }}
        >
          Export PNG
        </button>
      </div>
      <p className="muted">
        {layout.nodes.length - 1} node(s) within {layout.rings.length - 1} hop(s)
        {layout.hidden > 0 ? `; ${String(layout.hidden)} more not drawn (rings are capped)` : ''}.
        Enter recenters on a node.
      </p>
      {layout.nodes.length === 1 ? (
        <p>
          {route.dir === 'out'
            ? 'This principal cannot act as anyone else.'
            : 'No principal can act as this one.'}
        </p>
      ) : (
        <div className="reach__canvas">
          <svg
            ref={svg}
            width={size}
            height={size}
            viewBox={`${String(-size / 2)} ${String(-size / 2)} ${String(size)} ${String(size)}`}
            role="group"
            aria-label="Reach diagram"
          >
            {layout.rings.slice(1).map((_, d) => (
              <circle key={d} className="reach__ring" r={(d + 1) * ringGap} />
            ))}
            {layout.edges.map((e) => {
              const a = pos.get(e.from);
              const b = pos.get(e.to);
              const edge = ix.edges.get(e.id);
              if (!a || !b || !edge) return null;
              const [x1, y1, x2, y2] =
                route.dir === 'out' ? [a.x, a.y, b.x, b.y] : [b.x, b.y, a.x, a.y];
              return (
                <EdgeStroke
                  key={e.id}
                  kind={edge.kind}
                  d={`M${String(x1)} ${String(y1)} L${String(x2)} ${String(y2)}`}
                  conditional={edge.status === 'conditional'}
                  dimmed={!!route.sel && route.sel !== edge.from && route.sel !== edge.to}
                />
              );
            })}
            {layout.nodes.map((n) => {
              const node = ix.nodes.get(n.id);
              if (!node) return null;
              const label = displayName(node, pseudonyms);
              return (
                <g
                  key={n.id}
                  data-node={n.id}
                  className="reach__node"
                  tabIndex={0}
                  role="button"
                  aria-label={`${node.kind} ${label}, tier ${String(node.tier)}, ${String(n.ring)} hop(s)`}
                  onClick={() => {
                    update((r) => ({ ...r, sel: n.id }));
                  }}
                  onDoubleClick={() => {
                    navigate({ ...to('reach', n.id), dir: route.dir, sel: n.id });
                  }}
                  onKeyDown={onKey(n)}
                >
                  <Glyph
                    kind={node.kind}
                    tier={node.tier as Tier}
                    radius={
                      n.ring === 0
                        ? 16
                        : nodeRadius(node.blast?.reachable_principals ?? 0, ix.maxReach)
                    }
                    x={n.x}
                    y={n.y}
                    state={route.sel === n.id ? 'selected' : 'normal'}
                    stale={node.flags.includes('stale')}
                    label={label}
                  />
                  {(labels || n.ring === 0 || route.sel === n.id) && (
                    <text className="reach__label" x={n.x} y={n.y + 30} textAnchor="middle">
                      {label.length > 24 ? `${label.slice(0, 23)}…` : label}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      )}
      <section aria-labelledby="reach-table">
        <h2 id="reach-table" className="section__title">
          By distance
        </h2>
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Hops</th>
              <th scope="col">Principal</th>
              <th scope="col">Kind</th>
              <th scope="col">Tier</th>
            </tr>
          </thead>
          <tbody>
            {layout.nodes.slice(1).map((n) => {
              const node = ix.nodes.get(n.id);
              if (!node) return null;
              return (
                <tr key={n.id} aria-selected={route.sel === n.id}>
                  <td>{n.ring}</td>
                  <td>
                    <a href={`#/reach/${n.id}${route.dir === 'in' ? '?dir=in&' : '?'}sel=${n.id}`}>
                      {displayName(node, pseudonyms)}
                    </a>
                  </td>
                  <td>{node.kind}</td>
                  <td>{node.tier}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </div>
  );
}
