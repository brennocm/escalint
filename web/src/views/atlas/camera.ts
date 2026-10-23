// Camera: world → screen is s = (w - c) * zoom + viewport/2.

export interface Cam {
  readonly x: number;
  readonly y: number;
  readonly zoom: number;
}

export const zoomLimits = { min: 0.02, max: 8 } as const;

export function toScreen(c: Cam, vw: number, vh: number, x: number, y: number): [number, number] {
  return [(x - c.x) * c.zoom + vw / 2, (y - c.y) * c.zoom + vh / 2];
}

export function toWorld(c: Cam, vw: number, vh: number, sx: number, sy: number): [number, number] {
  return [(sx - vw / 2) / c.zoom + c.x, (sy - vh / 2) / c.zoom + c.y];
}

/** Zooms by factor keeping the world point under (sx, sy) fixed. */
export function zoomAt(
  c: Cam,
  vw: number,
  vh: number,
  sx: number,
  sy: number,
  factor: number,
): Cam {
  const zoom = Math.min(zoomLimits.max, Math.max(zoomLimits.min, c.zoom * factor));
  const [wx, wy] = toWorld(c, vw, vh, sx, sy);
  return { zoom, x: wx - (sx - vw / 2) / zoom, y: wy - (sy - vh / 2) / zoom };
}

/** Camera that fits a set of points with a margin. */
export function fit(
  xs: ArrayLike<number>,
  ys: ArrayLike<number>,
  vw: number,
  vh: number,
  margin = 40,
): Cam {
  if (xs.length === 0) return { x: 0, y: 0, zoom: 1 };
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (let i = 0; i < xs.length; i++) {
    minX = Math.min(minX, xs[i] ?? 0);
    maxX = Math.max(maxX, xs[i] ?? 0);
    minY = Math.min(minY, ys[i] ?? 0);
    maxY = Math.max(maxY, ys[i] ?? 0);
  }
  const w = Math.max(1, maxX - minX);
  const h = Math.max(1, maxY - minY);
  const zoom = Math.min(
    zoomLimits.max,
    Math.max(zoomLimits.min, Math.min((vw - 2 * margin) / w, (vh - 2 * margin) / h)),
  );
  return { x: (minX + maxX) / 2, y: (minY + maxY) / 2, zoom };
}

/** Ease between cameras (t in 0..1, cubic ease-in-out). */
export function lerpCam(a: Cam, b: Cam, t: number): Cam {
  const e = t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2;
  return {
    x: a.x + (b.x - a.x) * e,
    y: a.y + (b.y - a.y) * e,
    zoom: a.zoom * (b.zoom / a.zoom) ** e,
  };
}
