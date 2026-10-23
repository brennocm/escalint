import { describe, expect, it } from 'vitest';
import { forceLayout } from './force';
import { convexHull, insideConvex, paddedOutline } from './hull';
import { placeLabels, type LabelCandidate } from './labels';
import { hashSeed, mulberry32 } from './random';

describe('random', () => {
  it('is deterministic', () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    expect([a(), a(), a()]).toEqual([b(), b(), b()]);
    expect(hashSeed('abc')).toBe(hashSeed('abc'));
    expect(hashSeed('abc')).not.toBe(hashSeed('abd'));
  });
});

describe('forceLayout', () => {
  const ids = Array.from({ length: 60 }, (_, i) => `n_${String(i).padStart(16, '0')}`);
  const edges = ids.slice(1).map((_, i) => [Math.floor(i / 3), i + 1] as const);
  const groups = ids.map((_, i) => (i < 30 ? 'a' : 'b'));
  it('is deterministic and finite', () => {
    const one = forceLayout({ ids, edges, groups, iterations: 60 });
    const two = forceLayout({ ids, edges, groups, iterations: 60 });
    expect(Array.from(one.x)).toEqual(Array.from(two.x));
    expect(Array.from(one.y).every(Number.isFinite)).toBe(true);
  });
  it('keeps connected nodes closer than random pairs', () => {
    const { x, y } = forceLayout({ ids, edges, groups, iterations: 120 });
    const d = (a: number, b: number): number =>
      Math.hypot((x[a] ?? 0) - (x[b] ?? 0), (y[a] ?? 0) - (y[b] ?? 0));
    const linked = edges.reduce((s, [a, b]) => s + d(a, b), 0) / edges.length;
    let all = 0;
    let n = 0;
    for (let a = 0; a < ids.length; a += 7)
      for (let b = a + 3; b < ids.length; b += 11) {
        all += d(a, b);
        n++;
      }
    expect(linked).toBeLessThan(all / n);
  });
  it('handles empty input, coincident points and cancellation', () => {
    expect(forceLayout({ ids: [], edges: [], groups: [] }).x.length).toBe(0);
    const out = forceLayout(
      { ids: ['a', 'b'], edges: [], groups: ['g', 'g'], iterations: 5 },
      () => true,
    );
    expect(out.x.length).toBe(2);
  });
});

describe('hull', () => {
  it('computes convex hulls', () => {
    const square = convexHull([
      [0, 0],
      [1, 0],
      [1, 1],
      [0, 1],
      [0.5, 0.5],
      [1, 0.5],
      [0, 0],
    ]);
    expect(square).toHaveLength(4);
    expect(insideConvex(square, [0.5, 0.5])).toBe(true);
    expect(insideConvex(square, [2, 2])).toBe(false);
    expect(convexHull([[1, 1]])).toEqual([[1, 1]]);
  });
  it('pads the outline around every point', () => {
    const hull = convexHull([
      [0, 0],
      [10, 0],
      [5, 8],
    ]);
    const outline = paddedOutline(hull, 4);
    for (const p of hull) {
      const nearest = Math.min(...outline.map((q) => Math.hypot(q[0] - p[0], q[1] - p[1])));
      expect(nearest).toBeCloseTo(4, 5);
    }
    expect(paddedOutline([[0, 0]], 5)).toHaveLength(24);
    expect(
      paddedOutline(
        [
          [0, 0],
          [10, 0],
        ],
        2,
      ).length,
    ).toBeGreaterThan(10);
    expect(paddedOutline([], 2)).toEqual([]);
  });
});

describe('labels', () => {
  const c = (
    id: string,
    x: number,
    y: number,
    tier: number,
    extra: Partial<LabelCandidate> = {},
  ): LabelCandidate => ({ id, x, y, r: 6, width: 60, tier, blast: 0, degree: 0, ...extra });
  it('places by priority and avoids collisions', () => {
    const placed = placeLabels(
      [c('low', 100, 100, 3), c('high', 105, 102, 0), c('far', 300, 100, 3)],
      { width: 800, height: 600 },
    );
    expect(placed.map((p) => p.id).sort()).toEqual(['far', 'high']);
  });
  it('never covers a focused node and keeps labels on screen', () => {
    const placed = placeLabels(
      [c('focus', 100, 120, 3, { focused: true, r: 10 }), c('a', 100, 98, 0), c('edge', 5, 50, 0)],
      { width: 800, height: 600 },
    );
    expect(placed.map((p) => p.id)).toEqual(['focus']);
  });
  it('caps the number of labels', () => {
    const many = Array.from({ length: 50 }, (_, i) => c(`n${String(i)}`, 50 + i * 70, 100, 3));
    expect(placeLabels(many, { width: 10_000, height: 600 }, 14, 32, 10)).toHaveLength(10);
  });
});
