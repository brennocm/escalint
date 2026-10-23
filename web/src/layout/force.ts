import { hashSeed, mulberry32 } from './random';

// Force-directed layout in the spirit of ForceAtlas2 (linear attraction
// along edges, degree-weighted repulsion approximated with a Barnes–Hut
// quadtree, gravity towards each group's anchor). Deterministic: the seed
// comes from the node IDs, iteration order is fixed, and there is no
// time-based cooling (ADR 0015).

export interface ForceInput {
  readonly ids: readonly string[];
  /** Index pairs. */
  readonly edges: readonly (readonly [number, number])[];
  /** Group of each node (account): groups start on a circle. */
  readonly groups: readonly string[];
  readonly iterations?: number;
}

export interface ForceOutput {
  readonly x: Float32Array;
  readonly y: Float32Array;
}

interface Quad {
  x0: number;
  y0: number;
  size: number;
  mass: number;
  cx: number;
  cy: number;
  body: number; // node index when a leaf holds one body, else -1
  kids: (Quad | null)[] | null;
}

function newQuad(x0: number, y0: number, size: number): Quad {
  return { x0, y0, size, mass: 0, cx: 0, cy: 0, body: -1, kids: null };
}

function insert(
  q: Quad,
  i: number,
  x: Float32Array,
  y: Float32Array,
  m: Float32Array,
  depth = 0,
): void {
  const xi = x[i] ?? 0;
  const yi = y[i] ?? 0;
  const mi = m[i] ?? 1;
  if (q.mass === 0 && q.kids === null) {
    q.body = i;
    q.mass = mi;
    q.cx = xi;
    q.cy = yi;
    return;
  }
  if (q.kids === null) {
    if (depth > 40) {
      // Coincident points: merge instead of recursing forever.
      q.cx = (q.cx * q.mass + xi * mi) / (q.mass + mi);
      q.cy = (q.cy * q.mass + yi * mi) / (q.mass + mi);
      q.mass += mi;
      return;
    }
    q.kids = [null, null, null, null];
    const old = q.body;
    q.body = -1;
    q.mass = 0;
    q.cx = 0;
    q.cy = 0;
    if (old >= 0) place(q, old, x, y, m, depth);
  }
  place(q, i, x, y, m, depth);
}

function place(
  q: Quad,
  i: number,
  x: Float32Array,
  y: Float32Array,
  m: Float32Array,
  depth: number,
): void {
  const half = q.size / 2;
  const xi = x[i] ?? 0;
  const yi = y[i] ?? 0;
  const k = (xi >= q.x0 + half ? 1 : 0) + (yi >= q.y0 + half ? 2 : 0);
  const kids = q.kids ?? [null, null, null, null];
  q.kids = kids;
  let child = kids[k];
  if (!child) {
    child = newQuad(q.x0 + (k & 1 ? half : 0), q.y0 + (k & 2 ? half : 0), half);
    kids[k] = child;
  }
  insert(child, i, x, y, m, depth + 1);
  const mi = m[i] ?? 1;
  q.cx = (q.cx * q.mass + xi * mi) / (q.mass + mi);
  q.cy = (q.cy * q.mass + yi * mi) / (q.mass + mi);
  q.mass += mi;
}

function repulse(
  q: Quad,
  i: number,
  x: Float32Array,
  y: Float32Array,
  m: Float32Array,
  k: number,
  theta: number,
  out: [number, number],
): void {
  if (q.mass === 0 || q.body === i) return;
  const dx = (x[i] ?? 0) - q.cx;
  const dy = (y[i] ?? 0) - q.cy;
  const d2 = dx * dx + dy * dy + 0.01;
  if (q.kids === null || (q.size * q.size) / d2 < theta * theta) {
    const f = (k * (m[i] ?? 1) * q.mass) / d2;
    out[0] += dx * f;
    out[1] += dy * f;
    return;
  }
  for (const c of q.kids) if (c) repulse(c, i, x, y, m, k, theta, out);
}

export function forceLayout(
  input: ForceInput,
  cancelled: () => boolean = () => false,
): ForceOutput {
  const n = input.ids.length;
  const x = new Float32Array(n);
  const y = new Float32Array(n);
  if (n === 0) return { x, y };
  const rand = mulberry32(hashSeed(input.ids.join(',')));
  const groupNames = [...new Set(input.groups)].sort();
  const anchor = new Map<string, [number, number]>();
  const spread = 40 * Math.sqrt(n);
  groupNames.forEach((g, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, groupNames.length);
    anchor.set(g, groupNames.length === 1 ? [0, 0] : [spread * Math.cos(a), spread * Math.sin(a)]);
  });
  const degree = new Float32Array(n).fill(1);
  for (const [a, b] of input.edges) {
    degree[a] = (degree[a] ?? 1) + 1;
    degree[b] = (degree[b] ?? 1) + 1;
  }
  for (let i = 0; i < n; i++) {
    const [ax, ay] = anchor.get(input.groups[i] ?? '') ?? [0, 0];
    x[i] = ax + (rand() - 0.5) * spread * 0.5;
    y[i] = ay + (rand() - 0.5) * spread * 0.5;
  }
  const iterations =
    input.iterations ?? Math.min(400, Math.max(80, Math.round(20000 / Math.sqrt(n))));
  const repulsion = 80;
  const gravity = 0.02;
  const fx = new Float32Array(n);
  const fy = new Float32Array(n);
  const out: [number, number] = [0, 0];
  for (let it = 0; it < iterations && !cancelled(); it++) {
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (let i = 0; i < n; i++) {
      minX = Math.min(minX, x[i] ?? 0);
      minY = Math.min(minY, y[i] ?? 0);
      maxX = Math.max(maxX, x[i] ?? 0);
      maxY = Math.max(maxY, y[i] ?? 0);
    }
    const root = newQuad(minX - 1, minY - 1, Math.max(maxX - minX, maxY - minY) + 2);
    for (let i = 0; i < n; i++) insert(root, i, x, y, degree);
    for (let i = 0; i < n; i++) {
      out[0] = 0;
      out[1] = 0;
      repulse(root, i, x, y, degree, repulsion, 1.2, out);
      const [ax, ay] = anchor.get(input.groups[i] ?? '') ?? [0, 0];
      fx[i] = out[0] - gravity * (degree[i] ?? 1) * ((x[i] ?? 0) - ax);
      fy[i] = out[1] - gravity * (degree[i] ?? 1) * ((y[i] ?? 0) - ay);
    }
    for (const [a, b] of input.edges) {
      const dx = (x[b] ?? 0) - (x[a] ?? 0);
      const dy = (y[b] ?? 0) - (y[a] ?? 0);
      fx[a] = (fx[a] ?? 0) + dx * 0.05;
      fy[a] = (fy[a] ?? 0) + dy * 0.05;
      fx[b] = (fx[b] ?? 0) - dx * 0.05;
      fy[b] = (fy[b] ?? 0) - dy * 0.05;
    }
    // Step size shrinks with the iteration count, not with time.
    const step = 1 - it / iterations;
    for (let i = 0; i < n; i++) {
      const fxi = fx[i] ?? 0;
      const fyi = fy[i] ?? 0;
      const len = Math.hypot(fxi, fyi);
      const limit = 30 * step + 0.5;
      const s = len > limit ? limit / len : 1;
      x[i] = (x[i] ?? 0) + (fxi * s) / (degree[i] ?? 1);
      y[i] = (y[i] ?? 0) + (fyi * s) / (degree[i] ?? 1);
    }
  }
  return { x, y };
}
