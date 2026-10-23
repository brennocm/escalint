// Group areas: convex hull (Andrew's monotone chain) of the group's nodes,
// then a padded, rounded outline drawn as arcs around each hull vertex.

export type P = readonly [number, number];

const origin: P = [0, 0];
const at = (list: readonly P[], i: number): P => list[i] ?? origin;

function cross(o: P, a: P, b: P): number {
  return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
}

/** Convex hull in counter-clockwise order, without collinear points. */
export function convexHull(points: readonly P[]): P[] {
  const pts = [...points]
    .sort((a, b) => a[0] - b[0] || a[1] - b[1])
    .filter((p, i, arr) => i === 0 || p[0] !== arr[i - 1]?.[0] || p[1] !== arr[i - 1]?.[1]);
  if (pts.length < 3) return pts;
  const lower: P[] = [];
  for (const p of pts) {
    while (
      lower.length >= 2 &&
      cross(at(lower, lower.length - 2), at(lower, lower.length - 1), p) <= 0
    )
      lower.pop();
    lower.push(p);
  }
  const upper: P[] = [];
  for (let i = pts.length - 1; i >= 0; i--) {
    const p = at(pts, i);
    while (
      upper.length >= 2 &&
      cross(at(upper, upper.length - 2), at(upper, upper.length - 1), p) <= 0
    )
      upper.pop();
    upper.push(p);
  }
  return [...lower.slice(0, -1), ...upper.slice(0, -1)];
}

/** Outline of the hull grown by pad: offset edges joined by arcs. Returns
 * a polyline (closed) approximating the rounded shape. */
export function paddedOutline(hull: readonly P[], pad: number, arcSteps = 6): P[] {
  if (hull.length === 0) return [];
  if (hull.length === 1) {
    const [cx, cy] = at(hull, 0);
    return Array.from({ length: arcSteps * 4 }, (_, i) => {
      const a = (2 * Math.PI * i) / (arcSteps * 4);
      return [cx + pad * Math.cos(a), cy + pad * Math.sin(a)] as const;
    });
  }
  const out: P[] = [];
  const n = hull.length;
  for (let i = 0; i < n; i++) {
    const prev = at(hull, (i - 1 + n) % n);
    const cur = at(hull, i);
    const next = at(hull, (i + 1) % n);
    // Outward normals of the incoming and outgoing edges (CCW hull: right side).
    const n1 = normal(prev, cur);
    const n2 = normal(cur, next);
    const a1 = Math.atan2(n1[1], n1[0]);
    let a2 = Math.atan2(n2[1], n2[0]);
    if (n === 2) a2 = a1 + Math.PI;
    while (a2 < a1) a2 += 2 * Math.PI;
    for (let s = 0; s <= arcSteps; s++) {
      const a = a1 + ((a2 - a1) * s) / arcSteps;
      out.push([cur[0] + pad * Math.cos(a), cur[1] + pad * Math.sin(a)]);
    }
  }
  return out;
}

function normal(a: P, b: P): P {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  const len = Math.hypot(dx, dy) || 1;
  return [dy / len, -dx / len];
}

/** Whether p lies inside a convex polygon (CCW). */
export function insideConvex(poly: readonly P[], p: P): boolean {
  for (let i = 0; i < poly.length; i++) {
    if (cross(at(poly, i), at(poly, (i + 1) % poly.length), p) < 0) return false;
  }
  return poly.length >= 3;
}
