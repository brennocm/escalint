import { describe, expect, it, vi } from 'vitest';
import { buildIndexes } from '../../data/indexes';
import { vulnerable } from '../../data/fixtures';
import { themes } from '../../design/tokens';
import { emptyFilters } from '../../state/route';
import { drawMinimap, drawOverlay } from './Atlas';
import { buildScene } from './scene';

/** A recording stand-in for CanvasRenderingContext2D. */
function fakeContext(): { ctx: CanvasRenderingContext2D; calls: string[] } {
  const calls: string[] = [];
  const target: Record<string, unknown> = {};
  const ctx = new Proxy(target, {
    get(t, prop: string) {
      if (prop in t) return t[prop];
      if (prop === 'measureText') return (s: string) => ({ width: s.length * 6 });
      return (...args: unknown[]) => {
        calls.push(
          `${prop}(${args.length > 0 && typeof args[0] === 'string' ? args[0].slice(0, 20) : ''})`,
        );
      };
    },
    set(t, prop: string, value: unknown) {
      t[prop] = value;
      return true;
    },
  }) as unknown as CanvasRenderingContext2D;
  return { ctx, calls };
}

const ix = buildIndexes(vulnerable);
const scene = buildScene(ix);
const n = scene.nodes.length;
const pos = {
  x: Float32Array.from({ length: n }, (_, i) => (i % 9) * 60),
  y: Float32Array.from({ length: n }, (_, i) => Math.floor(i / 9) * 60),
};

describe('Atlas overlay', () => {
  it('draws group areas and prioritized labels', () => {
    const { ctx, calls } = fakeContext();
    drawOverlay(
      ctx,
      scene,
      pos,
      { x: 240, y: 200, zoom: 1 },
      1000,
      800,
      themes.light,
      emptyFilters,
      { hover: 0, selected: 1 },
      false,
      ix.maxReach,
    );
    expect(calls.some((c) => c.startsWith('fillText('))).toBe(true);
    expect(calls.some((c) => c.startsWith('strokeText('))).toBe(true);
    expect(calls.filter((c) => c.startsWith('closePath')).length).toBeGreaterThan(0); // hulls (several accounts)
  });
  it('switches to meta-nodes when zoomed out', () => {
    const { ctx, calls } = fakeContext();
    drawOverlay(
      ctx,
      scene,
      pos,
      { x: 240, y: 200, zoom: 0.05 },
      1000,
      800,
      themes.dark,
      emptyFilters,
      { hover: -1, selected: -1 },
      true,
      ix.maxReach,
    );
    expect(calls.filter((c) => c.startsWith('arc')).length).toBeGreaterThan(0);
    expect(calls.some((c) => c.includes('acct') || c.includes('·'))).toBe(true);
  });
  it('draws the minimap with the viewport', () => {
    const { ctx, calls } = fakeContext();
    drawMinimap(ctx, scene, pos, { x: 0, y: 0, zoom: 1 }, 800, 600, themes.light, emptyFilters);
    expect(calls.filter((c) => c.startsWith('fillRect')).length).toBeGreaterThan(n / 2);
    expect(calls.some((c) => c.startsWith('strokeRect'))).toBe(true);
  });
});

describe('export', () => {
  it('downloads SVG and canvas PNG files', async () => {
    const { exportSVG, exportCanvasPNG } = await import('../export');
    const create = vi.fn(() => 'blob:x');
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.append(document.createElementNS('http://www.w3.org/2000/svg', 'circle'));
    exportSVG(svg, 'x.svg');
    expect(create).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();
    const canvas = document.createElement('canvas');
    canvas.toBlob = (cb: BlobCallback) => {
      cb(new Blob(['x']));
    };
    exportCanvasPNG(canvas, 'x.png');
    expect(click).toHaveBeenCalledTimes(2);
    click.mockRestore();
  });
});
