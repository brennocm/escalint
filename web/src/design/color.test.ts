import { describe, expect, it } from 'vitest';
import {
  contrastRatio,
  deltaE2000,
  fromLinear,
  hexToRgb,
  perceivedDistance,
  rgbToLab,
  simulateVision,
  toLinear,
  type Lab,
} from './color';

describe('hexToRgb', () => {
  it('parses lower and upper case', () => {
    expect(hexToRgb('#ff8000')).toEqual([1, 128 / 255, 0]);
    expect(hexToRgb('#FF8000')).toEqual([1, 128 / 255, 0]);
  });

  it.each(['fff', '#fff', '#gggggg', '#12345', ''])('rejects %j', (hex) => {
    expect(() => hexToRgb(hex)).toThrow(/invalid hex color/);
  });
});

describe('transfer functions', () => {
  it('round-trips', () => {
    for (const c of [0, 0.01, 0.2, 0.5, 0.9, 1]) {
      expect(fromLinear(toLinear(c))).toBeCloseTo(c, 10);
    }
  });

  it('clamps out-of-range linear values', () => {
    expect(fromLinear(-0.5)).toBe(0);
    expect(fromLinear(2)).toBeCloseTo(1, 10);
  });
});

describe('contrastRatio (WCAG 2.x)', () => {
  it.each([
    ['#000000', '#ffffff', 21],
    ['#ffffff', '#ffffff', 1],
    // Reference value from the WebAIM contrast checker.
    ['#767676', '#ffffff', 4.54],
  ])('%s on %s = %d', (a, b, want) => {
    expect(contrastRatio(a, b)).toBeCloseTo(want, 2);
  });

  it('is symmetric', () => {
    expect(contrastRatio('#123456', '#abcdef')).toBeCloseTo(
      contrastRatio('#abcdef', '#123456'),
      12,
    );
  });
});

describe('rgbToLab', () => {
  it.each([
    ['#ffffff', [100, 0, 0]],
    ['#000000', [0, 0, 0]],
    // Reference: sRGB red in CIELAB (D65).
    ['#ff0000', [53.24, 80.09, 67.2]],
  ] as const)('%s', (hex, want) => {
    const lab = rgbToLab(hexToRgb(hex));
    lab.forEach((v, i) => {
      expect(v).toBeCloseTo(want[i] ?? 0, 1);
    });
  });
});

describe('deltaE2000', () => {
  // Test pairs 1, 7, 13, 17, 25 and 34 from Sharma, Wu and Dalal (2005), table 1.
  const sharma: [Lab, Lab, number][] = [
    [[50, 2.6772, -79.7751], [50, 0, -82.7485], 2.0425],
    [[50, 0, 0], [50, -1, 2], 2.3669],
    [[50, 2.5, 0], [56, -27, -3], 31.903],
    [[50, 2.5, 0], [73, 25, -18], 27.1492],
    [[60.2574, -34.0099, 36.2677], [60.4626, -34.1751, 39.4387], 1.2644],
    [[2.0776, 0.0795, -1.135], [0.9033, -0.0636, -0.5514], 0.9082],
  ];
  it.each(sharma)('%j vs %j = %d', (a, b, want) => {
    expect(deltaE2000(a, b)).toBeCloseTo(want, 4);
    expect(deltaE2000(b, a)).toBeCloseTo(want, 4);
  });

  it('is zero for identical colors', () => {
    expect(deltaE2000([42, 10, -10], [42, 10, -10])).toBe(0);
  });
});

describe('simulateVision', () => {
  it('leaves normal vision unchanged', () => {
    expect(simulateVision([0.2, 0.4, 0.6], 'normal')).toEqual([0.2, 0.4, 0.6]);
  });

  it('keeps achromatic colors achromatic (Machado rows sum to 1)', () => {
    for (const vision of ['protanopia', 'deuteranopia'] as const) {
      const [r, g, b] = simulateVision([0.5, 0.5, 0.5], vision);
      expect(r).toBeCloseTo(0.5, 2);
      expect(g).toBeCloseTo(0.5, 2);
      expect(b).toBeCloseTo(0.5, 2);
    }
  });

  it('collapses red and green for a deuteranope', () => {
    const normal = perceivedDistance('#d62728', '#2ca02c', 'normal');
    const deutan = perceivedDistance('#d62728', '#2ca02c', 'deuteranopia');
    expect(deutan).toBeLessThan(normal / 2);
  });
});
