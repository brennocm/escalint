import { describe, expect, it } from 'vitest';
import {
  circlePath,
  glyphDash,
  glyphPath,
  polygonPath,
  regularPolygon,
  roundedSquarePath,
  sinkInnerRadius,
  star,
  tierRingRadius,
} from './glyphs';
import { nodeKinds } from './tokens';

const distance = (p: { x: number; y: number }) => Math.hypot(p.x, p.y);

describe('regularPolygon', () => {
  it.each([3, 4, 5, 6, 8])('%d sides lie on the circumcircle', (sides) => {
    const points = regularPolygon(sides, 10);
    expect(points).toHaveLength(sides);
    for (const p of points) {
      expect(distance(p)).toBeCloseTo(10, 9);
    }
  });

  it('puts the first vertex straight up without rotation', () => {
    const [first] = regularPolygon(5, 10);
    expect(first?.x).toBeCloseTo(0, 9);
    expect(first?.y).toBeCloseTo(-10, 9);
  });

  it('is centered (vertices sum to zero)', () => {
    const points = regularPolygon(6, 7, 30);
    expect(points.reduce((s, p) => s + p.x, 0)).toBeCloseTo(0, 9);
    expect(points.reduce((s, p) => s + p.y, 0)).toBeCloseTo(0, 9);
  });
});

describe('star', () => {
  it('alternates outer and inner radius', () => {
    const points = star(8, 10, 5);
    expect(points).toHaveLength(16);
    points.forEach((p, i) => {
      expect(distance(p)).toBeCloseTo(i % 2 === 0 ? 10 : 5, 9);
    });
  });
});

describe('path builders', () => {
  it('polygonPath closes the shape and uses fixed precision', () => {
    expect(
      polygonPath([
        { x: 0, y: -1 },
        { x: 1 / 3, y: 0.5 },
        { x: -0.5, y: 0.5 },
      ]),
    ).toBe('M0 -1 L0.333 0.5 L-0.5 0.5 Z');
  });

  it('never prints negative zero', () => {
    expect(polygonPath([{ x: -0.0001, y: 0 }])).toBe('M0 0 Z');
  });

  it('circlePath is two arcs', () => {
    expect(circlePath(4)).toBe('M-4 0 A4 4 0 1 0 4 0 A4 4 0 1 0 -4 0 Z');
  });

  it('roundedSquarePath clamps the corner to the half size', () => {
    expect(roundedSquarePath(2, 5)).toBe(roundedSquarePath(2, 2));
  });
});

describe('glyphPath', () => {
  it('gives every node kind a distinct outline', () => {
    const outlines = new Map<string, string>();
    for (const kind of nodeKinds) {
      outlines.set(kind, glyphPath(kind, 10));
    }
    // user, external_account and tier0_sink share the circle outline; they
    // differ by dash (external) and by the inner ring (sink).
    const distinct = new Set(outlines.values());
    expect(distinct.size).toBe(nodeKinds.length - 2);
    expect(glyphDash('external_account', 10)).toBeDefined();
    expect(glyphDash('user', 10)).toBeUndefined();
    expect(sinkInnerRadius(10)).toBeLessThan(10);
  });

  it('is deterministic', () => {
    for (const kind of nodeKinds) {
      expect(glyphPath(kind, 9.5)).toBe(glyphPath(kind, 9.5));
    }
  });

  it('keeps every glyph inside its tier ring', () => {
    for (const kind of nodeKinds) {
      const coords =
        glyphPath(kind, 10)
          .match(/-?\d+(\.\d+)?/g)
          ?.map(Number) ?? [];
      const extent = Math.max(...coords.map(Math.abs));
      expect(extent, kind).toBeLessThan(tierRingRadius(10));
    }
  });
});
