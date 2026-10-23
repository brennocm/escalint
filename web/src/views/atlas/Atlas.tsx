import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent,
  type WheelEvent,
} from 'react';
import { useTheme } from '../../design/theme';
import { motion, nodeKinds, nodeLabels, nodeRadius, tiers, type Theme } from '../../design/tokens';
import { convexHull, paddedOutline, type P } from '../../layout/hull';
import { placeLabels, type LabelCandidate } from '../../layout/labels';
import { SpatialGrid } from '../../layout/spatial';
import { displayName } from '../../shell/names';
import type { Filters } from '../../state/route';
import { exportCanvasPNG } from '../export';
import type { ViewProps } from '../registry';
import { fit, lerpCam, toScreen, toWorld, zoomAt, type Cam } from './camera';
import { runLayout } from './layoutClient';
import { AtlasRenderer } from './renderer';
import {
  buildScene,
  edgeAttrs,
  metaNodes,
  nodeAttrs,
  shortestPath,
  visible,
  type Scene,
} from './scene';

/** Below this zoom, nodes collapse into one meta-node per account. */
const metaZoom = 0.12;
/** Above this many nodes the Atlas explains how it degrades. */
const largeGraph = 10_000;

/** What the Atlas tells the user on large graphs, or null. */
export function degradationNotice(nodes: number): string | null {
  if (nodes <= largeGraph) return null;
  return (
    `Large graph: ${nodes.toLocaleString('en-US')} nodes. The layout can take a minute; ` +
    'zoomed out, each account is one meta-node and expands as you zoom in; labels show only ' +
    'for the most important principals in view. Findings, Trace and search (Ctrl+K) go to a ' +
    'principal directly.'
  );
}

function reducedMotion(): boolean {
  return (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

export function drawOverlay(
  ctx: CanvasRenderingContext2D,
  s: Scene,
  pos: { x: Float32Array; y: Float32Array },
  cam: Cam,
  w: number,
  h: number,
  theme: Theme,
  f: Filters,
  focus: { hover: number; selected: number },
  pseudonyms: boolean,
  maxReach: number,
): void {
  const dpr = window.devicePixelRatio || 1;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  ctx.font = '12px Inter, system-ui, sans-serif';
  const meta = cam.zoom < metaZoom;
  // Group areas by account, under everything else.
  const byAccount = new Map<string, P[]>();
  s.nodes.forEach((n, i) => {
    if (!n.account || !visible(n, f)) return;
    const pt = toScreen(cam, w, h, pos.x[i] ?? 0, pos.y[i] ?? 0);
    const pts = byAccount.get(n.account);
    if (pts) pts.push(pt);
    else byAccount.set(n.account, [pt]);
  });
  if (byAccount.size > 1 && !meta) {
    for (const [acct, pts] of [...byAccount.entries()].sort()) {
      const outline = paddedOutline(convexHull(pts), 24);
      if (outline.length < 3) continue;
      ctx.beginPath();
      for (const [i, [x, y]] of outline.entries()) {
        if (i) ctx.lineTo(x, y);
        else ctx.moveTo(x, y);
      }
      ctx.closePath();
      ctx.fillStyle = theme.colors.surfaceRaised;
      ctx.globalAlpha = 0.35;
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.strokeStyle = theme.colors.border;
      ctx.stroke();
      const top = outline.reduce((a, b) => (b[1] < a[1] ? b : a));
      ctx.fillStyle = theme.colors.textMuted;
      ctx.fillText(pseudonyms ? `acct ${acct.slice(-4)}` : acct, top[0] - 30, top[1] - 6);
    }
  }
  if (meta) {
    for (const m of metaNodes(s, pos.x, pos.y, f)) {
      const [x, y] = toScreen(cam, w, h, m.x, m.y);
      const r = 10 + Math.sqrt(m.count) * 3;
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = theme.colors.surface;
      ctx.fill();
      ctx.lineWidth = m.tier0 ? 3 : 1.5;
      ctx.strokeStyle = m.tier0 ? theme.tier[0] : theme.colors.border;
      ctx.stroke();
      ctx.lineWidth = 1;
      ctx.fillStyle = theme.colors.text;
      ctx.textAlign = 'center';
      ctx.fillText(
        `${pseudonyms && /^\d{12}$/.test(m.key) ? `acct ${m.key.slice(-4)}` : m.key} · ${String(m.count)}`,
        x,
        y + r + 14,
      );
      ctx.textAlign = 'left';
    }
    return;
  }
  // Labels with priority and collision; halo behind the text.
  const cands: LabelCandidate[] = [];
  s.nodes.forEach((n, i) => {
    if (!visible(n, f)) return;
    const [x, y] = toScreen(cam, w, h, pos.x[i] ?? 0, pos.y[i] ?? 0);
    if (x < -50 || y < -50 || x > w + 50 || y > h + 50) return;
    const label = displayName(n, pseudonyms);
    const r =
      Math.min(
        48,
        Math.max(
          2,
          (n.kind === 'tier0_sink'
            ? 16
            : nodeRadius(n.blast?.reachable_principals ?? 0, maxReach)) * Math.sqrt(cam.zoom),
        ),
      ) * 1.75;
    cands.push({
      id: String(i),
      x,
      y,
      r,
      width: ctx.measureText(label).width,
      tier: n.tier,
      blast: n.blast?.reachable_principals ?? 0,
      degree: (s.out[i]?.length ?? 0) + (s.inn[i]?.length ?? 0),
      focused: i === focus.hover || i === focus.selected,
    });
  });
  const placed = placeLabels(cands, { width: w, height: h }, 14, 32, cam.zoom > 1 ? 300 : 120);
  ctx.lineJoin = 'round';
  for (const p of placed) {
    const n = s.nodes[Number(p.id)];
    if (!n) continue;
    const label = displayName(n, pseudonyms);
    ctx.lineWidth = 4;
    ctx.strokeStyle = theme.colors.bg;
    ctx.strokeText(label, p.x, p.y + 11);
    ctx.fillStyle = theme.colors.text;
    ctx.fillText(label, p.x, p.y + 11);
  }
  ctx.lineWidth = 1;
}

export function drawMinimap(
  ctx: CanvasRenderingContext2D,
  s: Scene,
  pos: { x: Float32Array; y: Float32Array },
  cam: Cam,
  vw: number,
  vh: number,
  theme: Theme,
  f: Filters,
): void {
  const mw = 160;
  const mh = 110;
  const dpr = window.devicePixelRatio || 1;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = theme.colors.surface;
  ctx.fillRect(0, 0, mw, mh);
  ctx.strokeStyle = theme.colors.border;
  ctx.strokeRect(0.5, 0.5, mw - 1, mh - 1);
  const all = fit(pos.x, pos.y, mw, mh, 8);
  ctx.fillStyle = theme.colors.textMuted;
  s.nodes.forEach((n, i) => {
    if (!visible(n, f)) return;
    const [x, y] = toScreen(all, mw, mh, pos.x[i] ?? 0, pos.y[i] ?? 0);
    ctx.fillStyle = n.tier === 0 ? theme.tier[0] : theme.colors.textMuted;
    ctx.fillRect(x - 1, y - 1, 2, 2);
  });
  const [x0, y0] = toWorld(cam, vw, vh, 0, 0);
  const [x1, y1] = toWorld(cam, vw, vh, vw, vh);
  const [a, b] = toScreen(all, mw, mh, x0, y0);
  const [c, d] = toScreen(all, mw, mh, x1, y1);
  ctx.strokeStyle = theme.colors.focus;
  ctx.strokeRect(a, b, c - a, d - b);
}

export function Atlas({ ix, route, pseudonyms, update }: ViewProps) {
  const theme = useTheme();
  const scene = useMemo(() => buildScene(ix), [ix]);
  const f = route.filters;
  const glCanvas = useRef<HTMLCanvasElement>(null);
  const overlay = useRef<HTMLCanvasElement>(null);
  const minimap = useRef<HTMLCanvasElement>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const renderer = useRef<AtlasRenderer | null>(null);
  const [glError, setGlError] = useState<string | null>(null);
  const [pos, setPos] = useState<{ x: Float32Array; y: Float32Array } | null>(null);
  const [cam, setCam] = useState<Cam>(route.camera ?? { x: 0, y: 0, zoom: 1 });
  const [hover, setHover] = useState(-1);
  const [anchor, setAnchor] = useState(-1);
  const [pathEdges, setPathEdges] = useState<ReadonlySet<number>>(new Set());
  const [critical, setCritical] = useState(false);
  const drag = useRef<{ x: number; y: number; cam: Cam; moved: boolean } | null>(null);
  const selected = route.sel ? (scene.index.get(route.sel) ?? -1) : -1;
  const size = (): [number, number] => [
    wrap.current?.clientWidth ?? 800,
    wrap.current?.clientHeight ?? 600,
  ];

  // Layout (worker), deterministic per analysis.
  useEffect(() => {
    const ac = new AbortController();
    const edgeIdx = scene.edges
      .filter((e) => e.kind !== 'member_of')
      .map((_, k) => [scene.edgeFrom[k] ?? 0, scene.edgeTo[k] ?? 0] as const);
    runLayout(
      {
        ids: scene.nodes.map((n) => n.id),
        edges: edgeIdx,
        groups: scene.nodes.map((n) => n.account || n.kind),
      },
      ac.signal,
    ).then(
      (out) => {
        setPos(out);
        if (!route.camera) {
          const [w, h] = size();
          setCam(fit(out.x, out.y, w, h));
        }
      },
      () => undefined,
    );
    return () => {
      ac.abort();
    };
    // The camera from the URL is read once, on load.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scene]);

  useEffect(() => {
    if (!glCanvas.current) return undefined;
    try {
      renderer.current = new AtlasRenderer(glCanvas.current);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      queueMicrotask(() => {
        setGlError(message);
      });
    }
    return () => {
      renderer.current?.destroy();
      renderer.current = null;
    };
  }, []);

  const criticalEdges = useMemo(() => {
    const set = new Set<number>();
    if (!critical) return set;
    const byId = new Map(scene.edges.map((e, k) => [e.id, k]));
    for (const p of ix.analysis.paths)
      if (p.severity === 'critical') for (const id of p.edges) set.add(byId.get(id) ?? -1);
    set.delete(-1);
    return set;
  }, [critical, scene, ix]);
  const highlight = pathEdges.size ? pathEdges : criticalEdges;

  // Upload attributes when data, filters or focus change.
  const attrs = useMemo(() => {
    if (!pos) return null;
    const focus = { hover, selected, pathEdges: highlight };
    const nodes = nodeAttrs(scene, ix, theme, pos.x, pos.y, f, focus);
    return { nodes, edges: edgeAttrs(scene, ix, theme, nodes, focus) };
  }, [pos, scene, ix, theme, f, hover, selected, highlight]);

  useEffect(() => {
    if (attrs) renderer.current?.setData(attrs.nodes, attrs.edges);
  }, [attrs]);

  // Draw every layer.
  useEffect(() => {
    if (!pos) return;
    const [w, h] = size();
    renderer.current?.draw(
      cam,
      {
        fill: theme.colors.nodeFill,
        stroke: theme.colors.nodeStroke,
        focus: theme.colors.focus,
        bg: theme.colors.bg,
      },
      0.1,
      cam.zoom >= metaZoom,
    );
    const o = overlay.current;
    const ctx = o?.getContext('2d');
    if (o && ctx) {
      const dpr = window.devicePixelRatio || 1;
      o.width = Math.round(w * dpr);
      o.height = Math.round(h * dpr);
      drawOverlay(
        ctx,
        scene,
        pos,
        cam,
        w,
        h,
        theme,
        f,
        { hover, selected },
        pseudonyms,
        ix.maxReach,
      );
    }
    const mm = minimap.current?.getContext('2d');
    if (mm && minimap.current) {
      const dpr = window.devicePixelRatio || 1;
      minimap.current.width = 160 * dpr;
      minimap.current.height = 110 * dpr;
      drawMinimap(mm, scene, pos, cam, w, h, theme, f);
    }
  }, [pos, cam, attrs, theme, scene, f, hover, selected, pseudonyms, ix.maxReach]);

  // Keep the camera in the URL (rounded; replaces the history entry).
  useEffect(() => {
    const t = setTimeout(() => {
      update((r) => ({
        ...r,
        camera: {
          x: Math.round(cam.x * 100) / 100,
          y: Math.round(cam.y * 100) / 100,
          zoom: Math.round(cam.zoom * 100) / 100,
        },
      }));
    }, 300);
    return () => {
      clearTimeout(t);
    };
  }, [cam, update]);

  const animateTo = useCallback((target: Cam) => {
    if (reducedMotion()) {
      setCam(target);
      return;
    }
    const start = performance.now();
    setCam((from) => {
      const step = (now: number): void => {
        const t = Math.min(1, (now - start) / motion.camera);
        setCam(lerpCam(from, target, t));
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
      return from;
    });
  }, []);

  const grid = useMemo(() => (pos ? new SpatialGrid(pos.x, pos.y, 40) : null), [pos]);
  const pick = (sx: number, sy: number): number => {
    if (!grid || cam.zoom < metaZoom) return -1;
    const [w, h] = size();
    const [wx, wy] = toWorld(cam, w, h, sx, sy);
    return grid.nearest(wx, wy, 14 / Math.sqrt(cam.zoom), (i) => {
      const n = scene.nodes[i];
      return !n || !visible(n, f);
    });
  };
  const local = (e: { clientX: number; clientY: number }): [number, number] => {
    const r = wrap.current?.getBoundingClientRect();
    return [e.clientX - (r?.left ?? 0), e.clientY - (r?.top ?? 0)];
  };

  const onPointerDown = (e: PointerEvent<HTMLCanvasElement>): void => {
    e.currentTarget.setPointerCapture(e.pointerId);
    drag.current = { x: e.clientX, y: e.clientY, cam, moved: false };
  };
  const onPointerMove = (e: PointerEvent<HTMLCanvasElement>): void => {
    const d = drag.current;
    if (d) {
      const dx = e.clientX - d.x;
      const dy = e.clientY - d.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
      if (d.moved) setCam({ ...d.cam, x: d.cam.x - dx / d.cam.zoom, y: d.cam.y - dy / d.cam.zoom });
      return;
    }
    const [sx, sy] = local(e);
    setHover(pick(sx, sy));
  };
  const onPointerUp = (e: PointerEvent<HTMLCanvasElement>): void => {
    const d = drag.current;
    drag.current = null;
    if (d?.moved) return;
    const [sx, sy] = local(e);
    const i = pick(sx, sy);
    if (i < 0) {
      setPathEdges(new Set());
      update((r) => ({ ...r, sel: null }));
      return;
    }
    if (e.shiftKey) {
      if (anchor >= 0 && anchor !== i) {
        setPathEdges(new Set(shortestPath(scene, anchor, i)));
        setAnchor(-1);
      } else {
        setAnchor(i);
      }
    }
    const id = scene.nodes[i]?.id ?? null;
    update((r) => ({ ...r, sel: id }));
  };
  const onWheel = (e: WheelEvent<HTMLCanvasElement>): void => {
    const [w, h] = size();
    const [sx, sy] = local(e);
    setCam((c) => zoomAt(c, w, h, sx, sy, Math.exp(-e.deltaY * 0.0015)));
  };
  const onKey = (e: KeyboardEvent<HTMLDivElement>): void => {
    const [w, h] = size();
    const pan = 60 / cam.zoom;
    const moves: Record<string, Cam> = {
      ArrowLeft: { ...cam, x: cam.x - pan },
      ArrowRight: { ...cam, x: cam.x + pan },
      ArrowUp: { ...cam, y: cam.y - pan },
      ArrowDown: { ...cam, y: cam.y + pan },
      '+': zoomAt(cam, w, h, w / 2, h / 2, 1.25),
      '=': zoomAt(cam, w, h, w / 2, h / 2, 1.25),
      '-': zoomAt(cam, w, h, w / 2, h / 2, 0.8),
    };
    const next = moves[e.key];
    if (next) {
      e.preventDefault();
      setCam(next);
    } else if (e.key === '0' && pos) {
      e.preventDefault();
      animateTo(fit(pos.x, pos.y, w, h));
    }
  };
  const focusNode = (id: string): void => {
    const i = scene.index.get(id);
    if (i === undefined || !pos) return;
    update((r) => ({ ...r, sel: id }));
    animateTo({ x: pos.x[i] ?? 0, y: pos.y[i] ?? 0, zoom: Math.max(cam.zoom, 1.2) });
  };
  const setFilters = (patch: Partial<Filters>): void => {
    update((r) => ({ ...r, filters: { ...r.filters, ...patch } }));
  };

  // Sorting tens of thousands of nodes on every camera move froze large
  // accounts: the table depends only on the data and the filters.
  const notice = degradationNotice(scene.nodes.length);
  const { shown, tableRows } = useMemo(() => {
    const list = scene.nodes.filter((n) => visible(n, f) && n.kind !== 'tier0_sink');
    const rows = [...list]
      .sort(
        (a, b) =>
          a.tier - b.tier ||
          (b.blast?.reachable_principals ?? 0) - (a.blast?.reachable_principals ?? 0),
      )
      .slice(0, 200);
    return { shown: list, tableRows: rows };
  }, [scene, f]);
  const toggleTier = (t: number): number[] =>
    f.tiers.includes(t) ? f.tiers.filter((x) => x !== t) : [...f.tiers, t];

  return (
    <div className="atlas">
      <div className="atlas__bar">
        <h1 className="view__title">Atlas</h1>
        <fieldset className="filters__group">
          <legend>Tier</legend>
          {tiers.map((t) => (
            <label key={t}>
              <input
                type="checkbox"
                checked={f.tiers.includes(t)}
                onChange={() => {
                  setFilters({ tiers: toggleTier(t) });
                }}
              />{' '}
              {t}
            </label>
          ))}
        </fieldset>
        <label className="filters__field">
          Kind{' '}
          <select
            value={f.kinds[0] ?? ''}
            onChange={(e) => {
              setFilters({ kinds: e.target.value ? [e.target.value] : [] });
            }}
          >
            <option value="">All</option>
            {nodeKinds.map((k) => (
              <option key={k} value={k}>
                {nodeLabels[k]}
              </option>
            ))}
          </select>
        </label>
        {ix.accounts.length > 1 && (
          <label className="filters__field">
            Account{' '}
            <select
              value={f.accounts[0] ?? ''}
              onChange={(e) => {
                setFilters({ accounts: e.target.value ? [e.target.value] : [] });
              }}
            >
              <option value="">All</option>
              {ix.accounts.map((a) => (
                <option key={a} value={a}>
                  {pseudonyms ? `acct ${a.slice(-4)}` : a}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="filters__field">
          <input
            type="checkbox"
            checked={f.stale}
            onChange={() => {
              setFilters({ stale: !f.stale });
            }}
          />{' '}
          Stale only
        </label>
        <button
          type="button"
          className="button"
          aria-pressed={critical}
          onClick={() => {
            setCritical(!critical);
            setPathEdges(new Set());
          }}
        >
          Critical paths
        </button>
        <button
          type="button"
          className="button button--ghost"
          onClick={() => {
            if (pos) {
              const [w, h] = size();
              animateTo(fit(pos.x, pos.y, w, h));
            }
          }}
        >
          Fit
        </button>
        <button
          type="button"
          className="button button--ghost"
          aria-label="Zoom in"
          onClick={() => {
            const [w, h] = size();
            setCam((c) => zoomAt(c, w, h, w / 2, h / 2, 1.25));
          }}
        >
          +
        </button>
        <button
          type="button"
          className="button button--ghost"
          aria-label="Zoom out"
          onClick={() => {
            const [w, h] = size();
            setCam((c) => zoomAt(c, w, h, w / 2, h / 2, 0.8));
          }}
        >
          −
        </button>
        <button
          type="button"
          className="button button--ghost"
          onClick={() => {
            if (glCanvas.current) exportCanvasPNG(glCanvas.current, 'escalint-atlas.png');
          }}
        >
          Export PNG
        </button>
      </div>
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {glError && (
        <p className="notice" role="status">
          The graph needs WebGL2, which is not available here ({glError}). The table below lists the
          same principals.
        </p>
      )}
      {/* A canvas widget: the stage takes keyboard input (pan, zoom, fit). */}
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
      <div
        ref={wrap}
        className="atlas__stage"
        role="application"
        aria-label="Graph of principals. Drag to pan, scroll or plus and minus to zoom, 0 to fit, Shift+click two nodes for the shortest path. The table below lists the same data."
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={0}
        onKeyDown={onKey}
      >
        <canvas ref={glCanvas} className="atlas__gl" aria-hidden="true" />
        <canvas
          ref={overlay}
          className="atlas__overlay"
          aria-hidden="true"
          data-testid="atlas-overlay"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={() => {
            setHover(-1);
          }}
          onWheel={onWheel}
        />
        <canvas
          ref={minimap}
          className="atlas__minimap"
          aria-hidden="true"
          width={160}
          height={110}
        />
        {!pos && <p className="atlas__loading">Laying out {scene.nodes.length} nodes…</p>}
      </div>
      <p className="muted" aria-live="polite">
        {shown.length} principal(s) shown
        {anchor >= 0 ? '; Shift+click a second node for the shortest path' : ''}
        {pathEdges.size ? `; path of ${String(pathEdges.size)} edge(s) highlighted` : ''}.
      </p>
      <details className="atlas__table">
        <summary>Principals in view (table)</summary>
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Principal</th>
              <th scope="col">Kind</th>
              <th scope="col">Tier</th>
              <th scope="col">Reachable principals</th>
            </tr>
          </thead>
          <tbody>
            {tableRows.map((n) => (
              <tr key={n.id} aria-selected={route.sel === n.id}>
                <td>
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => {
                      focusNode(n.id);
                    }}
                  >
                    {displayName(n, pseudonyms)}
                  </button>
                </td>
                <td>{n.kind}</td>
                <td>{n.tier}</td>
                <td>{n.blast?.reachable_principals ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}
