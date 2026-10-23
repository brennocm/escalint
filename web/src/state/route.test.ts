import { describe, expect, it } from 'vitest';
import { defaultRoute, emptyFilters, formatHash, parseHash, to, views, type Route } from './route';

const n = 'n_0123456789abcdef';
const p = 'p_fedcba9876543210';

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function randomRoute(r: () => number): Route {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
  const some = <T>(xs: readonly T[]): T[] => [...new Set(xs.filter(() => r() < 0.3))];
  const view = pick(views);
  const hex = (): string =>
    Array.from({ length: 16 }, () => pick(Array.from('0123456789abcdef'))).join('');
  return {
    view,
    id: view === 'path' ? `p_${hex()}` : view === 'reach' ? `n_${hex()}` : null,
    dir: view === 'reach' ? pick(['in', 'out'] as const) : 'out',
    sel: r() < 0.5 ? `${pick(['n', 'e', 'p', 'f'])}_${hex()}` : null,
    filters: {
      tiers: some([0, 1, 2, 3]).sort(),
      kinds: some(['user', 'role', 'group', 'service']).sort(),
      accounts: some(['111111111111', '222222222222']).sort(),
      severities: some(['critical', 'high', 'medium', 'low', 'info']).sort(),
      rules: some(['EL-PE-001', 'EL-TR-002']).sort(),
      text: r() < 0.3 ? pick(['admin', 'a b&c', 'role/x?y=z#w', 'ção']) : '',
      stale: r() < 0.3,
      suppressed: r() < 0.3,
    },
    camera:
      r() < 0.4
        ? {
            x: Math.round((r() - 0.5) * 10000) / 100,
            y: Math.round(r() * 1000) / 100,
            zoom: Math.round(r() * 400 + 10) / 100,
          }
        : null,
  };
}

describe('route', () => {
  it('serialize then parse is the identity', () => {
    const r = rng(42);
    for (let i = 0; i < 500; i++) {
      const route = randomRoute(r);
      const hash = formatHash(route);
      const parsed = parseHash(hash);
      expect(parsed.warning).toBeNull();
      expect(parsed.route).toEqual(route);
      expect(formatHash(parsed.route)).toBe(hash);
    }
  });
  it('formats canonical URLs', () => {
    expect(formatHash(defaultRoute)).toBe('#/');
    expect(formatHash(to('path', p))).toBe(`#/path/${p}`);
    expect(formatHash({ ...to('reach', n), dir: 'in' })).toBe(`#/reach/${n}?dir=in`);
    expect(
      formatHash({
        ...to('findings'),
        filters: { ...emptyFilters, severities: ['high', 'critical'] },
      }),
    ).toBe('#/findings?sev=critical%2Chigh');
  });
  it('rounds the camera', () => {
    const { route } = parseHash('#/atlas?cam=1.23456,-2.5,0.333333');
    expect(route.camera).toEqual({ x: 1.23, y: -2.5, zoom: 0.33 });
  });
  it.each([
    '#/nope',
    '#/path',
    '#/path/p_short',
    '#/reach/n_0123456789abcdef?dir=sideways',
    '#/atlas/extra',
    '#/atlas?evil=1',
    '#/atlas?sel=<script>',
    '#/atlas?tier=7',
    '#/findings?sev=urgent',
    '#/atlas?cam=1,2',
    '#/atlas?cam=1,2,0',
    '#/atlas?stale=yes',
    `#/findings?q=${'x'.repeat(201)}`,
    '#/a/b/c',
  ])('degrades %s to the overview with a warning', (hash) => {
    const res = parseHash(hash);
    expect(res.route).toEqual(defaultRoute);
    expect(res.warning).toMatch(/invalid link/);
  });
  it('treats empty hashes as the overview', () => {
    expect(parseHash('')).toEqual({ route: defaultRoute, warning: null });
    expect(parseHash('#/')).toEqual({ route: defaultRoute, warning: null });
    expect(parseHash('#/atlas?tier=')).toMatchObject({ warning: null });
  });
});
