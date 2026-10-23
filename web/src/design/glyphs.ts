// Glyph geometry for the eight node kinds (shape = kind; never color alone).
// Pure functions that return SVG path data centered on (0, 0). The WebGL
// programs of the Atlas (Phase 12) implement the same shapes as SDFs; their
// TypeScript ports will be tested against these outlines.
import type { NodeKind } from './tokens';

export interface Point {
  x: number;
  y: number;
}

/** Rounds to 3 decimals so generated SVG is byte-for-byte deterministic. */
function fmt(n: number): string {
  const v = Math.round(n * 1000) / 1000;
  return Object.is(v, -0) ? '0' : String(v);
}

/** Vertices of a regular polygon with circumradius r. `rotation` in degrees;
 * 0 puts the first vertex straight up. */
export function regularPolygon(sides: number, r: number, rotation = 0): Point[] {
  const points: Point[] = [];
  for (let i = 0; i < sides; i++) {
    const angle = ((rotation + (360 * i) / sides - 90) * Math.PI) / 180;
    points.push({ x: r * Math.cos(angle), y: r * Math.sin(angle) });
  }
  return points;
}

/** Vertices of a star alternating between outer and inner radius. */
export function star(pointsCount: number, outer: number, inner: number): Point[] {
  const points: Point[] = [];
  for (let i = 0; i < pointsCount * 2; i++) {
    const r = i % 2 === 0 ? outer : inner;
    const angle = ((180 * i) / pointsCount - 90) * (Math.PI / 180);
    points.push({ x: r * Math.cos(angle), y: r * Math.sin(angle) });
  }
  return points;
}

export function polygonPath(points: Point[]): string {
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'}${fmt(p.x)} ${fmt(p.y)}`).join(' ') + ' Z';
}

export function circlePath(r: number): string {
  return `M${fmt(-r)} 0 A${fmt(r)} ${fmt(r)} 0 1 0 ${fmt(r)} 0 A${fmt(r)} ${fmt(r)} 0 1 0 ${fmt(-r)} 0 Z`;
}

export function roundedSquarePath(half: number, corner: number): string {
  const h = half;
  const c = Math.min(corner, half);
  return [
    `M${fmt(-h + c)} ${fmt(-h)}`,
    `L${fmt(h - c)} ${fmt(-h)}`,
    `A${fmt(c)} ${fmt(c)} 0 0 1 ${fmt(h)} ${fmt(-h + c)}`,
    `L${fmt(h)} ${fmt(h - c)}`,
    `A${fmt(c)} ${fmt(c)} 0 0 1 ${fmt(h - c)} ${fmt(h)}`,
    `L${fmt(-h + c)} ${fmt(h)}`,
    `A${fmt(c)} ${fmt(c)} 0 0 1 ${fmt(-h)} ${fmt(h - c)}`,
    `L${fmt(-h)} ${fmt(-h + c)}`,
    `A${fmt(c)} ${fmt(c)} 0 0 1 ${fmt(-h + c)} ${fmt(-h)}`,
    'Z',
  ].join(' ');
}

/**
 * Shape scale per kind, chosen so every glyph has roughly the same visual area
 * as a circle of radius r (polygons look smaller than circles at equal
 * circumradius).
 */
export const glyphScale: Record<NodeKind, number> = {
  user: 1,
  role: 1.08,
  group: 0.9,
  service: 1.2,
  external_account: 1,
  federated: 1.12,
  any_principal: 1.25,
  tier0_sink: 1,
};

/** Outline of a glyph of nominal radius r. The tier0 sink is drawn as two
 * concentric rings; this returns the outer one (see sinkInnerRadius). */
export function glyphPath(kind: NodeKind, r: number): string {
  const s = r * glyphScale[kind];
  switch (kind) {
    case 'user':
    case 'external_account':
    case 'tier0_sink':
      return circlePath(s);
    case 'role':
      return polygonPath(regularPolygon(6, s, 30));
    case 'group':
      return roundedSquarePath(s, s * 0.35);
    case 'service':
      return polygonPath(regularPolygon(4, s));
    case 'federated':
      return polygonPath(regularPolygon(5, s));
    case 'any_principal':
      return polygonPath(star(8, s, s * 0.55));
  }
}

export function sinkInnerRadius(r: number): number {
  return r * 0.58;
}

/** Glyphs whose outline is dashed (an account outside the analyzed set). */
export function glyphDash(kind: NodeKind, r: number): string | undefined {
  return kind === 'external_account' ? `${fmt(r * 0.45)} ${fmt(r * 0.3)}` : undefined;
}

/** Gap between the glyph outline and its tier ring. */
export function tierRingRadius(r: number): number {
  return r * 1.25 + 2;
}
