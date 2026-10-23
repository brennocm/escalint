// Color science used to validate the palettes in unit tests (docs/design.md).
// Everything here is pure math on sRGB hex strings; nothing touches the DOM.

export type RGB = readonly [number, number, number]; // sRGB channels in [0, 1]
export type Lab = readonly [number, number, number]; // CIE L*a*b*, D65

/** Parses "#rrggbb" into sRGB channels in [0, 1]. */
export function hexToRgb(hex: string): RGB {
  const match = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!match) {
    throw new Error(`invalid hex color ${JSON.stringify(hex)}`);
  }
  const [, r = '', g = '', b = ''] = match;
  return [parseInt(r, 16) / 255, parseInt(g, 16) / 255, parseInt(b, 16) / 255];
}

/** sRGB transfer function (gamma) -> linear light. */
export function toLinear(c: number): number {
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

/** Linear light -> sRGB, clamped to [0, 1]. */
export function fromLinear(c: number): number {
  const v = Math.min(1, Math.max(0, c));
  return v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055;
}

/** WCAG 2.x relative luminance. */
export function relativeLuminance(rgb: RGB): number {
  const [r, g, b] = rgb.map(toLinear) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG 2.x contrast ratio between two colors (1 to 21). */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(hexToRgb(a));
  const lb = relativeLuminance(hexToRgb(b));
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** sRGB -> CIE L*a*b* (D65 white point). */
export function rgbToLab(rgb: RGB): Lab {
  const [r, g, b] = rgb.map(toLinear) as [number, number, number];
  const x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / 0.95047;
  const y = 0.2126729 * r + 0.7151522 * g + 0.072175 * b;
  const z = (0.0193339 * r + 0.119192 * g + 0.9503041 * b) / 1.08883;
  const f = (t: number) => (t > 216 / 24389 ? Math.cbrt(t) : ((24389 / 27) * t + 16) / 116);
  const fx = f(x);
  const fy = f(y);
  const fz = f(z);
  return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
}

const deg = (rad: number) => (rad * 180) / Math.PI;
const rad = (d: number) => (d * Math.PI) / 180;

/**
 * CIEDE2000 color difference, following Sharma, Wu and Dalal (2005),
 * "The CIEDE2000 color-difference formula: implementation notes".
 */
export function deltaE2000(lab1: Lab, lab2: Lab): number {
  const [l1, a1, b1] = lab1;
  const [l2, a2, b2] = lab2;
  const cBar = (Math.hypot(a1, b1) + Math.hypot(a2, b2)) / 2;
  const g = 0.5 * (1 - Math.sqrt(cBar ** 7 / (cBar ** 7 + 25 ** 7)));
  const a1p = (1 + g) * a1;
  const a2p = (1 + g) * a2;
  const c1p = Math.hypot(a1p, b1);
  const c2p = Math.hypot(a2p, b2);
  const hue = (a: number, b: number) =>
    a === 0 && b === 0 ? 0 : (deg(Math.atan2(b, a)) + 360) % 360;
  const h1p = hue(a1p, b1);
  const h2p = hue(a2p, b2);

  const dL = l2 - l1;
  const dC = c2p - c1p;
  let dh = 0;
  if (c1p * c2p !== 0) {
    dh = h2p - h1p;
    if (dh > 180) dh -= 360;
    else if (dh < -180) dh += 360;
  }
  const dH = 2 * Math.sqrt(c1p * c2p) * Math.sin(rad(dh / 2));

  const lBar = (l1 + l2) / 2;
  const cBarP = (c1p + c2p) / 2;
  let hBar = h1p + h2p;
  if (c1p * c2p !== 0) {
    if (Math.abs(h1p - h2p) <= 180) hBar = (h1p + h2p) / 2;
    else if (h1p + h2p < 360) hBar = (h1p + h2p + 360) / 2;
    else hBar = (h1p + h2p - 360) / 2;
  }
  const t =
    1 -
    0.17 * Math.cos(rad(hBar - 30)) +
    0.24 * Math.cos(rad(2 * hBar)) +
    0.32 * Math.cos(rad(3 * hBar + 6)) -
    0.2 * Math.cos(rad(4 * hBar - 63));
  const dTheta = 30 * Math.exp(-(((hBar - 275) / 25) ** 2));
  const rc = 2 * Math.sqrt(cBarP ** 7 / (cBarP ** 7 + 25 ** 7));
  const sl = 1 + (0.015 * (lBar - 50) ** 2) / Math.sqrt(20 + (lBar - 50) ** 2);
  const sc = 1 + 0.045 * cBarP;
  const sh = 1 + 0.015 * cBarP * t;
  const rt = -Math.sin(rad(2 * dTheta)) * rc;
  return Math.sqrt((dL / sl) ** 2 + (dC / sc) ** 2 + (dH / sh) ** 2 + rt * (dC / sc) * (dH / sh));
}

export type Vision = 'normal' | 'protanopia' | 'deuteranopia';

type Matrix3 = readonly [RGB, RGB, RGB];

/**
 * Machado, Oliveira and Fernandes (2009), "A Physiologically-based Model for
 * Simulation of Color Vision Deficiency", severity 1.0 matrices. They operate
 * on linear RGB.
 */
const cvdMatrices: Record<Exclude<Vision, 'normal'>, Matrix3> = {
  protanopia: [
    [0.152286, 1.052583, -0.204868],
    [0.114503, 0.786281, 0.099216],
    [-0.003882, -0.048116, 1.051998],
  ],
  deuteranopia: [
    [0.367322, 0.860646, -0.227968],
    [0.280085, 0.672501, 0.047413],
    [-0.01182, 0.04294, 0.968881],
  ],
};

/** Simulates how a color is perceived under the given vision. */
export function simulateVision(rgb: RGB, vision: Vision): RGB {
  if (vision === 'normal') {
    return rgb;
  }
  const lin = rgb.map(toLinear);
  const [r0, r1, r2] = cvdMatrices[vision].map((row) =>
    fromLinear(row[0] * (lin[0] ?? 0) + row[1] * (lin[1] ?? 0) + row[2] * (lin[2] ?? 0)),
  ) as [number, number, number];
  return [r0, r1, r2];
}

/** CIEDE2000 distance between two hex colors as seen under `vision`. */
export function perceivedDistance(a: string, b: string, vision: Vision): number {
  return deltaE2000(
    rgbToLab(simulateVision(hexToRgb(a), vision)),
    rgbToLab(simulateVision(hexToRgb(b), vision)),
  );
}

/** CIE L* of a hex color as seen under `vision`. */
export function perceivedLightness(hex: string, vision: Vision): number {
  return rgbToLab(simulateVision(hexToRgb(hex), vision))[0];
}
