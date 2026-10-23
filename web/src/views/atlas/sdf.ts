// Signed distance functions of the node glyphs, in units of the glyph
// radius (negative inside). The fragment shader in renderer.ts implements
// the same functions in GLSL; these TypeScript versions are the tested
// reference (keep both in sync).

export const kindCodes = {
  user: 0,
  role: 1,
  group: 2,
  service: 3,
  external_account: 4,
  federated: 5,
  any_principal: 6,
  tier0_sink: 7,
} as const;

export function sdCircle(x: number, y: number, r: number): number {
  return Math.hypot(x, y) - r;
}

/** Regular polygon with n sides, circumradius r, a vertex at the top. */
export function sdPolygon(x: number, y: number, r: number, n: number): number {
  const an = Math.PI / n;
  // Rotate so a vertex points up, then fold into one sector.
  let a = Math.atan2(x, y);
  a = (((a % (2 * an)) + 2 * an) % (2 * an)) - an;
  const len = Math.hypot(x, y);
  const px = len * Math.cos(a);
  return px - r * Math.cos(an);
}

export function sdRoundedSquare(x: number, y: number, half: number, corner: number): number {
  const qx = Math.abs(x) - half + corner;
  const qy = Math.abs(y) - half + corner;
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - corner;
}

export function sdDiamond(x: number, y: number, r: number): number {
  return (Math.abs(x) + Math.abs(y) - r) / Math.SQRT2;
}

/** Star with n points (outer radius r, inner radius r*k). */
export function sdStar(x: number, y: number, r: number, n: number, k: number): number {
  const an = Math.PI / n;
  let a = Math.atan2(x, y);
  a = ((a % (2 * an)) + 2 * an) % (2 * an);
  if (a > an) a = 2 * an - a; // mirror into [0, an]
  const len = Math.hypot(x, y);
  const px = len * Math.cos(a);
  const py = len * Math.sin(a);
  // Segment from the tip (r, 0) to the inner vertex at angle an.
  const ax = r;
  const ay = 0;
  const bx = r * k * Math.cos(an);
  const by = r * k * Math.sin(an);
  const t = Math.max(
    0,
    Math.min(
      1,
      ((px - ax) * (bx - ax) + (py - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2),
    ),
  );
  const dx = px - (ax + t * (bx - ax));
  const dy = py - (ay + t * (by - ay));
  const d = Math.hypot(dx, dy);
  // Inside when on the origin side of the segment.
  const side = (bx - ax) * (py - ay) - (by - ay) * (px - ax);
  return side > 0 ? -d : d;
}

/** Distance to a glyph of the given kind, radius 1 at scale s=1. */
export function glyphDistance(kind: number, x: number, y: number): number {
  switch (kind) {
    case kindCodes.user:
    case kindCodes.external_account:
      return sdCircle(x, y, 1);
    case kindCodes.role:
      return sdPolygon(x, y, 1, 6);
    case kindCodes.group:
      return sdRoundedSquare(x, y, 0.85, 0.25);
    case kindCodes.service:
      return sdDiamond(x, y, 1.1);
    case kindCodes.federated:
      return sdPolygon(x, y, 1, 5);
    case kindCodes.any_principal:
      return sdStar(x, y, 1.1, 8, 0.55);
    case kindCodes.tier0_sink:
      // Double ring: two annuli.
      return Math.min(Math.abs(sdCircle(x, y, 0.95)) - 0.12, Math.abs(sdCircle(x, y, 0.6)) - 0.12);
    default:
      return sdCircle(x, y, 1);
  }
}
