import { useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from '../../design/theme';
import { capabilityLabels, type Theme } from '../../design/tokens';
import { displayName } from '../../shell/names';
import { Empty } from '../../shell/States';
import { exportCanvasPNG } from '../export';
import type { ViewProps } from '../registry';
import { buildMatrix, cellAt, classes, type Cell, type Matrix } from './model';

const cellSize = 14;
const labelWidth = 220;
const headerHeight = 110;
/** Canvases taller than this fail in some browsers; export renders the
 * whole matrix only below it. */
const maxCanvasHeight = 16_384;

/** Draws the rows of the matrix between content offsets top and
 * top + viewHeight (header included when in range). */
function drawMatrix(
  ctx: CanvasRenderingContext2D,
  m: Matrix,
  theme: Theme,
  pseudonyms: boolean,
  view: { top: number; height: number; width: number },
  cell: { row: number; col: number } | null,
): void {
  ctx.fillStyle = theme.colors.bg;
  ctx.fillRect(0, view.top, view.width, view.height);
  ctx.font = '11px sans-serif';
  ctx.fillStyle = theme.colors.textMuted;
  // Column headers (rotated) and the column histogram.
  if (view.top < headerHeight) {
    const maxCol = Math.max(1, ...m.colTotals);
    m.services.forEach((svc, j) => {
      const x = labelWidth + j * cellSize;
      ctx.save();
      ctx.translate(x + cellSize - 3, headerHeight - 26);
      ctx.rotate(-Math.PI / 3);
      ctx.fillText(svc, 0, 0);
      ctx.restore();
      const h = ((m.colTotals[j] ?? 0) / maxCol) * 18;
      ctx.fillRect(x + 2, headerHeight - 4 - h, cellSize - 4, h);
    });
  }
  // Only rows in view are drawn.
  const first = Math.max(0, Math.floor((view.top - headerHeight) / cellSize) - 1);
  const last = Math.min(
    m.rows.length,
    Math.ceil((view.top + view.height - headerHeight) / cellSize) + 1,
  );
  const maxRow = Math.max(1, ...m.rowTotals);
  for (let r = first; r < last; r++) {
    const y = headerHeight + r * cellSize;
    const n = m.rows[r];
    if (!n) continue;
    ctx.fillStyle = theme.colors.text;
    const label = displayName(n, pseudonyms);
    ctx.fillText(label.length > 30 ? `${label.slice(0, 29)}…` : label, 4, y + cellSize - 3);
    for (let j = 0; j < m.services.length; j++) {
      const v = cellAt(m, r, j);
      const x = labelWidth + j * cellSize;
      if (v >= 0) {
        ctx.fillStyle = theme.intensity[classes[v as 0 | 1 | 2 | 3]];
        ctx.fillRect(x + 1, y + 1, cellSize - 2, cellSize - 2);
      } else {
        ctx.strokeStyle = theme.colors.border;
        ctx.strokeRect(x + 0.5, y + 0.5, cellSize - 1, cellSize - 1);
      }
    }
    ctx.fillStyle = theme.colors.textMuted;
    ctx.fillRect(
      labelWidth + m.services.length * cellSize + 6,
      y + 3,
      ((m.rowTotals[r] ?? 0) / maxRow) * 48,
      cellSize - 6,
    );
  }
  if (cell) {
    ctx.strokeStyle = theme.colors.focus;
    ctx.lineWidth = 2;
    ctx.strokeRect(
      labelWidth + cell.col * cellSize,
      headerHeight + cell.row * cellSize,
      cellSize,
      cellSize,
    );
    ctx.lineWidth = 1;
  }
}

export function Exposure({ ix, route, pseudonyms, update }: ViewProps) {
  const theme = useTheme();
  const tiers = route.filters.tiers;
  const m = useMemo(
    () => buildMatrix(ix, (n) => tiers.length === 0 || tiers.includes(n.tier)),
    [ix, tiers],
  );
  const canvas = useRef<HTMLCanvasElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const [cell, setCell] = useState<{ row: number; col: number } | null>(null);
  const [scroll, setScroll] = useState({ top: 0, height: 600 });
  const width = labelWidth + m.services.length * cellSize + 60;
  const height = headerHeight + m.rows.length * cellSize + 8;
  // The canvas covers only the visible part of the scroll area (a tall
  // matrix would exceed the browser's canvas size limit); a spacer of the
  // full height gives the scroll bar its range.
  const viewHeight = Math.min(height, scroll.height);

  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const measure = (): void => {
      setScroll({ top: el.scrollTop, height: el.clientHeight || 600 });
    };
    measure();
    window.addEventListener('resize', measure);
    return () => {
      window.removeEventListener('resize', measure);
    };
  }, []);

  useEffect(() => {
    const c = canvas.current;
    const ctx = c?.getContext('2d');
    if (!c || !ctx) return;
    const dpr = window.devicePixelRatio || 1;
    c.width = width * dpr;
    c.height = viewHeight * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, -scroll.top * dpr);
    drawMatrix(ctx, m, theme, pseudonyms, { top: scroll.top, height: viewHeight, width }, cell);
  }, [m, theme, pseudonyms, width, viewHeight, scroll, cell]);

  const exportPNG = (): void => {
    const out = document.createElement('canvas');
    const ctx = out.getContext('2d');
    if (!ctx) return;
    // The whole matrix when it fits in one canvas, else the visible part.
    const whole = height <= maxCanvasHeight;
    const view = whole ? { top: 0, height, width } : { top: scroll.top, height: viewHeight, width };
    out.width = width;
    out.height = view.height;
    ctx.setTransform(1, 0, 0, 1, 0, -view.top);
    drawMatrix(ctx, m, theme, pseudonyms, view, cell);
    exportCanvasPNG(out, 'escalint-exposure.png');
  };

  if (m.rows.length === 0)
    return <Empty title="No principals">Nothing matches the current filter.</Empty>;
  const pick = (clientX: number, clientY: number, rect: DOMRect): void => {
    const col = Math.floor((clientX - rect.left - labelWidth) / cellSize);
    const row = Math.floor((clientY - rect.top + scroll.top - headerHeight) / cellSize);
    if (col < 0 || row < 0 || col >= m.services.length || row >= m.rows.length) return;
    setCell({ row, col });
    const n = m.rows[row];
    if (n) update((r) => ({ ...r, sel: n.id }));
  };
  const selected = cell
    ? { node: m.rows[cell.row], svc: m.services[cell.col], v: cellAt(m, cell.row, cell.col) }
    : null;
  const levelName = (v: Cell): string =>
    v < 0 ? 'no access' : capabilityLabels[classes[v as 0 | 1 | 2 | 3]];
  return (
    <div className="exposure">
      <h1 className="view__title">Exposure</h1>
      <p className="muted">
        {m.rows.length} principal(s) × {m.services.length} service(s). Each cell is the strongest
        capability class the principal can use in the service, directly or through principals it can
        reach. Similar profiles are grouped (nearest-neighbor seriation on Jaccard distance).
      </p>
      <div className="actions">
        {classes.map((c) => (
          <span key={c} className="swatch">
            <svg width="12" height="12" aria-hidden="true">
              <rect width="12" height="12" fill={theme.intensity[c]} />
            </svg>
            {capabilityLabels[c]}
          </span>
        ))}
        <button type="button" className="button button--ghost" onClick={exportPNG}>
          Export PNG
        </button>
      </div>
      <div
        className="exposure__scroll"
        role="region"
        aria-label="Exposure matrix (scrollable); the table view lists the same data"
        // Scrollable regions must be keyboard-focusable (WCAG 2.1.1).
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={0}
        ref={scroller}
        onScroll={(e) => {
          setScroll({ top: e.currentTarget.scrollTop, height: e.currentTarget.clientHeight });
        }}
      >
        <div className="exposure__spacer" style={{ width, height }}>
          <canvas
            ref={canvas}
            className="exposure__canvas"
            width={width}
            height={viewHeight}
            style={{ width, height: viewHeight }}
            aria-hidden="true"
            data-testid="exposure-canvas"
            onClick={(e) => {
              pick(e.clientX, e.clientY, e.currentTarget.getBoundingClientRect());
            }}
          />
        </div>
      </div>
      {selected?.node && selected.svc && (
        <p className="exposure__detail" aria-live="polite">
          {displayName(selected.node, pseudonyms)}: {levelName(selected.v)} in{' '}
          <code>{selected.svc}</code>.{' '}
          <a href={`#/reach/${selected.node.id}?sel=${selected.node.id}`}>
            Principals it can reach
          </a>
        </p>
      )}
      <details className="exposure__table">
        <summary>Table view</summary>
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Principal</th>
              {classes.map((c) => (
                <th key={c} scope="col">
                  {capabilityLabels[c]}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {m.rows.slice(0, 500).map((n) => (
              <tr key={n.id}>
                <th scope="row">{displayName(n, pseudonyms)}</th>
                {classes.map((c) => (
                  <td key={c}>{n.blast?.capabilities[c].join(', ') ?? ''}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {m.rows.length > 500 && <p className="muted">First 500 rows; filter by tier to narrow.</p>}
      </details>
    </div>
  );
}
