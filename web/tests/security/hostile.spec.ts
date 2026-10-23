import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { hostileAnalysis } from './hostile';

// security-ui: hostile names reach every view through `escalint serve`;
// no script runs, no CSP violation, no request leaves the origin.
const root = fileURLToPath(new URL('../../..', import.meta.url));
const bin = process.env.ESCALINT_BIN ?? `${root}bin/escalint`;
let server: ChildProcess | null = null;
let url = '';
let analysis: { paths: { id: string; source: string }[] } = { paths: [] };

test.beforeAll(async () => {
  const fixture = readFileSync(`${root}web/src/data/fixtures/vulnerable.analysis.json`, 'utf8');
  const text = hostileAnalysis(fixture);
  analysis = JSON.parse(text) as typeof analysis;
  const file = join(mkdtempSync(join(tmpdir(), 'escalint-hostile-')), 'analysis.json');
  writeFileSync(file, text);
  server = spawn(bin, ['serve', file], { stdio: ['ignore', 'ignore', 'pipe'] });
  url = await new Promise<string>((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => {
      reject(new Error(`no URL: ${buf}`));
    }, 30_000);
    server?.stderr?.on('data', (d: Buffer) => {
      buf += d.toString();
      const m = /open (http:\/\/\S+)/.exec(buf);
      if (m?.[1]) {
        clearTimeout(timer);
        resolve(m[1]);
      }
    });
  });
});

test.afterAll(() => {
  server?.kill('SIGINT');
});

test('hostile strings never execute, violate the CSP or leak requests', async ({ page }) => {
  test.setTimeout(120_000);
  const dialogs: string[] = [];
  const external: string[] = [];
  page.on('dialog', (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  page.on('request', (r) => {
    if (
      !r.url().startsWith(new URL(url).origin) &&
      !r.url().startsWith('data:') &&
      !r.url().startsWith('blob:')
    )
      external.push(r.url());
  });
  await page.addInitScript(() => {
    const w = window as unknown as { __csp: string[] };
    w.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => {
      w.__csp.push(`${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message.slice(0, 300)));
  await page.goto(url);
  const origin = new URL(url).origin;
  const p = analysis.paths[0];
  const hashes = ['#/', '#/atlas', '#/findings', '#/exposure', '#/fix', '#/detect'];
  if (p) hashes.push(`#/path/${p.id}`, `#/reach/${p.source}`);
  for (const h of hashes) {
    await page.goto(`${origin}/${h}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible({ timeout: 15_000 });
    if (h.startsWith('#/path/')) {
      const edge = page.getByRole('button', { name: /edge: .*policy explainer/ }).first();
      await edge.click();
      await expect(page.getByRole('region', { name: 'Policy explainer' })).toBeVisible();
    }
  }
  await page.keyboard.press('Control+k');
  await page.getByRole('dialog', { name: 'Search' }).getByRole('combobox').fill('img');
  await page.keyboard.press('Escape');
  const xss = await page.evaluate(() => (window as unknown as { __xss?: number }).__xss);
  const csp = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
  expect(xss).toBeUndefined();
  expect(dialogs).toEqual([]);
  expect(csp).toEqual([]);
  expect(external).toEqual([]);
  expect(errors).toEqual([]);
  // The payload is shown as text.
  await page.goto(`${origin}/#/findings`);
  await expect(page.getByText('<img src=x onerror="window.__xss=1">').first()).toBeAttached();
});
