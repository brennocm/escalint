import { describe, expect, it } from 'vitest';
import { fit, lerpCam, toScreen, toWorld, zoomAt } from './camera';
import {
  glyphDistance,
  kindCodes,
  sdCircle,
  sdDiamond,
  sdPolygon,
  sdRoundedSquare,
  sdStar,
} from './sdf';

describe('sdf', () => {
  it('is negative inside, zero on the edge, positive outside', () => {
    expect(sdCircle(0, 0, 1)).toBe(-1);
    expect(sdCircle(1, 0, 1)).toBe(0);
    expect(sdCircle(2, 0, 1)).toBe(1);
    // Hexagon: vertex at the top (0,1), flat sides at x = ±cos(30°).
    expect(sdPolygon(0, 1, 1, 6)).toBeCloseTo(0, 6);
    expect(sdPolygon(Math.cos(Math.PI / 6), 0, 1, 6)).toBeCloseTo(0, 6);
    expect(sdPolygon(0, 0, 1, 6)).toBeLessThan(0);
    expect(sdPolygon(0, 2, 1, 6)).toBeGreaterThan(0);
    expect(sdRoundedSquare(0, 0, 1, 0.2)).toBeCloseTo(-1, 6);
    expect(sdRoundedSquare(1, 0, 1, 0.2)).toBeCloseTo(0, 6);
    expect(sdRoundedSquare(2, 2, 1, 0)).toBeCloseTo(Math.SQRT2, 6);
    expect(sdDiamond(1, 0, 1)).toBeCloseTo(0, 6);
    expect(sdDiamond(0.5, 0.5, 1)).toBeCloseTo(0, 6);
    expect(sdStar(0, 1, 1, 8, 0.5)).toBeCloseTo(0, 6); // a tip
    expect(sdStar(0, 0, 1, 8, 0.5)).toBeLessThan(0);
    expect(sdStar(0, 1.5, 1, 8, 0.5)).toBeGreaterThan(0);
  });
  it('maps every kind to a shape', () => {
    for (const code of Object.values(kindCodes)) {
      expect(glyphDistance(code, 3, 3)).toBeGreaterThan(0);
    }
    expect(glyphDistance(kindCodes.tier0_sink, 0, 0)).toBeGreaterThan(0); // hollow centre
    expect(glyphDistance(kindCodes.tier0_sink, 0.95, 0)).toBeLessThan(0);
    expect(glyphDistance(99, 0, 0)).toBe(-1);
  });
});

describe('camera', () => {
  const cam = { x: 10, y: 20, zoom: 2 };
  it('round-trips world and screen', () => {
    const [sx, sy] = toScreen(cam, 800, 600, 15, 25);
    expect(toWorld(cam, 800, 600, sx, sy)).toEqual([15, 25]);
  });
  it('zooms around the cursor', () => {
    const z = zoomAt(cam, 800, 600, 100, 100, 2);
    expect(toWorld(z, 800, 600, 100, 100).map((v) => Math.round(v * 1e6) / 1e6)).toEqual(
      toWorld(cam, 800, 600, 100, 100).map((v) => Math.round(v * 1e6) / 1e6),
    );
    expect(zoomAt(cam, 800, 600, 0, 0, 1e9).zoom).toBe(8);
  });
  it('fits points and eases', () => {
    const f = fit([0, 100], [0, 50], 240, 140, 20);
    expect(f).toEqual({ x: 50, y: 25, zoom: 2 });
    expect(fit([], [], 10, 10)).toEqual({ x: 0, y: 0, zoom: 1 });
    expect(lerpCam(cam, f, 0)).toEqual(cam);
    const end = lerpCam(cam, f, 1);
    expect(end.x).toBeCloseTo(50);
    expect(end.zoom).toBeCloseTo(2);
  });
});
