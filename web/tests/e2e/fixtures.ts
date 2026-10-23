import { readFileSync } from 'node:fs';
import type { Page } from '@playwright/test';

export const vulnerable = readFileSync(
  new URL('../../src/data/fixtures/vulnerable.analysis.json', import.meta.url),
  'utf8',
);
export const diffed = readFileSync(
  new URL('../../src/data/fixtures/diff.analysis.json', import.meta.url),
  'utf8',
);

interface Ids {
  readonly path: string;
  readonly source: string;
}

export function ids(): Ids {
  const a = JSON.parse(vulnerable) as { paths: { id: string; source: string; length: number }[] };
  const p = a.paths.find((x) => x.length >= 2) ?? a.paths[0];
  if (!p) throw new Error('fixture has no path');
  return { path: p.id, source: p.source };
}

/** Opens a view with the fixture served as analysis.json. */
export async function openView(page: Page, hash: string, body = vulnerable): Promise<void> {
  await page.route('**/analysis.json', (route) =>
    route.fulfill({ contentType: 'application/json', body }),
  );
  await page.goto(`/${hash}`);
  await page.getByRole('navigation', { name: 'Views' }).waitFor();
}

export function views(): { name: string; hash: string; heading: RegExp; body?: string }[] {
  const { path, source } = ids();
  return [
    { name: 'overview', hash: '#/', heading: /^Overview$/ },
    { name: 'atlas', hash: '#/atlas', heading: /^Atlas$/ },
    { name: 'trace', hash: `#/path/${path}`, heading: /^Trace/ },
    { name: 'reach', hash: `#/reach/${source}`, heading: /^Reach:/ },
    { name: 'exposure', hash: '#/exposure', heading: /^Exposure$/ },
    { name: 'findings', hash: '#/findings', heading: /^Findings$/ },
    { name: 'fix', hash: '#/fix', heading: /^Fix plan$/ },
    { name: 'detect', hash: '#/detect', heading: /^Detect$/ },
    { name: 'diff', hash: '#/diff', heading: /^Diff$/, body: diffed },
  ];
}
