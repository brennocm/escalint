import { SCHEMA_VERSION, type Analysis } from '../contract/analysis';

/** Where the analysis comes from: the HTML report inlines it, `serve` and
 * the demo serve it as a file. */
export type Source =
  | { readonly kind: 'inline'; readonly elementId: string }
  | { readonly kind: 'url'; readonly url: string };

export class LoadError extends Error {
  override readonly name = 'LoadError';
}

/** Light validation: the UI trusts the Go contract for structure (it is
 * validated against the JSON Schema in Go tests) and checks only what lets
 * it fail clearly: a JSON object of a known schema version with the main
 * arrays present. */
export function parseAnalysis(text: string): Analysis {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    throw new LoadError(`analysis.json is not valid JSON: ${(err as Error).message}`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new LoadError('analysis.json must be a JSON object');
  }
  const record = value as Record<string, unknown>;
  const version = record.schema_version;
  if (version !== SCHEMA_VERSION) {
    throw new LoadError(
      `unsupported schema_version ${JSON.stringify(version)}: this UI reads version ${SCHEMA_VERSION}; ` +
        'regenerate the file with a matching escalint version',
    );
  }
  for (const key of ['nodes', 'edges', 'paths', 'findings', 'rules']) {
    if (!Array.isArray(record[key])) {
      throw new LoadError(`analysis.json has no ${key} array`);
    }
  }
  return value as Analysis;
}

/** Loads an analysis. fetchImpl is injectable for tests. */
export async function loadAnalysis(
  source: Source,
  doc: Document = document,
  fetchImpl: typeof fetch = fetch,
): Promise<Analysis> {
  if (source.kind === 'inline') {
    const el = doc.getElementById(source.elementId);
    if (!el?.textContent) {
      throw new LoadError(`no embedded data (#${source.elementId})`);
    }
    return parseAnalysis(el.textContent);
  }
  const res = await fetchImpl(source.url, { credentials: 'same-origin', cache: 'no-store' });
  if (!res.ok) {
    throw new LoadError(`could not load ${source.url}: HTTP ${String(res.status)}`);
  }
  return parseAnalysis(await res.text());
}

/** Picks the source: inline data when the page carries it, else the
 * analysis.json next to the page (serve, demo). */
export function detectSource(doc: Document = document): Source {
  if (doc.getElementById('escalint-data')) {
    return { kind: 'inline', elementId: 'escalint-data' };
  }
  const demo = new URLSearchParams(doc.location.search).get('dataset');
  if (demo && /^[a-z0-9-]{1,40}$/.test(demo)) {
    return { kind: 'url', url: `data/${demo}.json` };
  }
  return { kind: 'url', url: 'analysis.json' };
}
