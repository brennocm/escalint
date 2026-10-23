// Hash router: the whole view state lives in the URL so any view can be
// shared or bookmarked. Format: #/<view>[/<id>]?key=value&… with keys in a
// fixed order and defaults omitted, so every state has one canonical URL.

export const views = [
  'overview',
  'atlas',
  'path',
  'reach',
  'exposure',
  'findings',
  'fix',
  'diff',
] as const;
export type View = (typeof views)[number];

export type Direction = 'in' | 'out';

export interface Camera {
  readonly x: number;
  readonly y: number;
  readonly zoom: number;
}

export interface Filters {
  readonly tiers: readonly number[];
  readonly kinds: readonly string[];
  readonly accounts: readonly string[];
  readonly severities: readonly string[];
  readonly rules: readonly string[];
  readonly text: string;
  readonly stale: boolean;
  readonly suppressed: boolean;
}

export interface Route {
  readonly view: View;
  /** Path ID for `path`, node ID for `reach`. */
  readonly id: string | null;
  readonly dir: Direction;
  /** Selected node, edge, path or finding. */
  readonly sel: string | null;
  readonly filters: Filters;
  readonly camera: Camera | null;
}

export const emptyFilters: Filters = {
  tiers: [],
  kinds: [],
  accounts: [],
  severities: [],
  rules: [],
  text: '',
  stale: false,
  suppressed: false,
};

export const defaultRoute: Route = {
  view: 'overview',
  id: null,
  dir: 'out',
  sel: null,
  filters: emptyFilters,
  camera: null,
};

const idPattern = /^[nepf]_[0-9a-f]{16}$/;
const kindPattern = /^[a-z0-9_]{1,24}$/;
const accountPattern = /^\d{12}$/;
const severityNames = ['critical', 'high', 'medium', 'low', 'info'];
const rulePattern = /^EL-[A-Z]+-\d{3}$/;

export function isEntityId(s: string): boolean {
  return idPattern.test(s);
}

export interface ParseResult {
  readonly route: Route;
  /** Set when the URL was invalid and the route degraded. */
  readonly warning: string | null;
}

const roundCam = (n: number): number => Math.round(n * 100) / 100;

function list(value: string | null, valid: (s: string) => boolean): string[] | null {
  if (value === null || value === '') return [];
  const items = value.split(',');
  return items.every(valid) ? [...new Set(items)].sort() : null;
}

/** Parses a location hash. Invalid URLs degrade to the Overview with a
 * warning instead of throwing. */
export function parseHash(hash: string): ParseResult {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash;
  if (raw === '' || raw === '/') return { route: defaultRoute, warning: null };
  const bad = (why: string): ParseResult => ({
    route: defaultRoute,
    warning: `Ignored an invalid link (${why}); showing the overview.`,
  });
  const [pathPart = '', query = ''] = raw.split('?', 2);
  const segments = pathPart.split('/').filter((s) => s !== '');
  const view = (segments[0] ?? 'overview') as View;
  if (!views.includes(view) || segments.length > 2) return bad('unknown view');
  let id: string | null = null;
  if (view === 'path' || view === 'reach') {
    id = segments[1] ?? null;
    if (id === null || !isEntityId(id))
      return bad(`missing or malformed ${view === 'path' ? 'path' : 'node'} ID`);
  } else if (segments.length > 1) {
    return bad('unexpected segment');
  }
  const q = new URLSearchParams(query);
  for (const key of q.keys()) {
    if (
      ![
        'dir',
        'sel',
        'tier',
        'kind',
        'account',
        'sev',
        'rule',
        'q',
        'stale',
        'suppressed',
        'cam',
      ].includes(key)
    ) {
      return bad(`unknown parameter ${key}`);
    }
  }
  const dir = q.get('dir') ?? 'out';
  if (dir !== 'in' && dir !== 'out') return bad('dir');
  const sel = q.get('sel');
  if (sel !== null && !isEntityId(sel)) return bad('selection');
  const tiers = list(q.get('tier'), (s) => /^[0-3]$/.test(s));
  const kinds = list(q.get('kind'), (s) => kindPattern.test(s));
  const accounts = list(q.get('account'), (s) => accountPattern.test(s));
  const severities = list(q.get('sev'), (s) => severityNames.includes(s));
  const rules = list(q.get('rule'), (s) => rulePattern.test(s));
  if (!tiers || !kinds || !accounts || !severities || !rules) return bad('filter');
  const text = q.get('q') ?? '';
  if (text.length > 200) return bad('search text too long');
  let camera: Camera | null = null;
  const cam = q.get('cam');
  if (cam !== null) {
    const parts = cam.split(',').map(Number);
    if (parts.length !== 3 || parts.some((n) => !Number.isFinite(n)) || (parts[2] ?? 0) <= 0)
      return bad('camera');
    camera = {
      x: roundCam(parts[0] ?? 0),
      y: roundCam(parts[1] ?? 0),
      zoom: roundCam(parts[2] ?? 1),
    };
  }
  const flag = (k: string): boolean | null => {
    const v = q.get(k);
    return v === null ? false : v === '1' ? true : null;
  };
  const stale = flag('stale');
  const suppressed = flag('suppressed');
  if (stale === null || suppressed === null) return bad('flag');
  return {
    route: {
      view,
      id,
      dir: view === 'reach' ? dir : 'out',
      sel,
      filters: {
        tiers: tiers.map(Number),
        kinds,
        accounts,
        severities,
        rules,
        text,
        stale,
        suppressed,
      },
      camera,
    },
    warning: null,
  };
}

/** Formats a route as its canonical hash. */
export function formatHash(r: Route): string {
  let path = `#/${r.view === 'overview' ? '' : r.view}`;
  if ((r.view === 'path' || r.view === 'reach') && r.id) path += `/${r.id}`;
  const q: [string, string][] = [];
  if (r.view === 'reach' && r.dir !== 'out') q.push(['dir', r.dir]);
  if (r.sel) q.push(['sel', r.sel]);
  const f = r.filters;
  const join = (xs: readonly (string | number)[]): string => [...xs].map(String).sort().join(',');
  if (f.tiers.length) q.push(['tier', join(f.tiers)]);
  if (f.kinds.length) q.push(['kind', join(f.kinds)]);
  if (f.accounts.length) q.push(['account', join(f.accounts)]);
  if (f.severities.length) q.push(['sev', join(f.severities)]);
  if (f.rules.length) q.push(['rule', join(f.rules)]);
  if (f.text) q.push(['q', f.text]);
  if (f.stale) q.push(['stale', '1']);
  if (f.suppressed) q.push(['suppressed', '1']);
  if (r.camera)
    q.push([
      'cam',
      `${String(roundCam(r.camera.x))},${String(roundCam(r.camera.y))},${String(roundCam(r.camera.zoom))}`,
    ]);
  const qs = new URLSearchParams(q).toString();
  return qs ? `${path}?${qs}` : path;
}

/** Route helper: a view with no state. */
export function to(view: View, id: string | null = null): Route {
  return { ...defaultRoute, view, id };
}
