import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { expect, test } from '@playwright/test';

// The single-file report opens from file:// with every view, under its
// hash-based CSP, with zero violations and zero network requests.
const root = fileURLToPath(new URL('../../..', import.meta.url));
const bin = process.env.ESCALINT_BIN ?? `${root}bin/escalint`;

for (const redact of [false, true]) {
  test(`report${redact ? ' (redacted)' : ''} works offline under its CSP`, async ({ page }) => {
    const out = join(mkdtempSync(join(tmpdir(), 'escalint-report-')), 'report.html');
    execFileSync(bin, [
      'report',
      '--html',
      `${root}examples/vulnerable-account/snapshot.json`,
      '--config-file',
      `${root}examples/vulnerable-account/.escalint.yaml`,
      '-o',
      out,
      ...(redact ? ['--redact'] : []),
    ]);
    await page.addInitScript(() => {
      const w = window as unknown as { __csp: string[] };
      w.__csp = [];
      document.addEventListener('securitypolicyviolation', (e) => {
        w.__csp.push(`${e.violatedDirective} ${e.blockedURI}`);
      });
    });
    const network: string[] = [];
    page.on('request', (r) => {
      if (
        !r.url().startsWith('file:') &&
        !r.url().startsWith('data:') &&
        !r.url().startsWith('blob:')
      )
        network.push(r.url());
    });
    const base = pathToFileURL(out).toString();
    await page.goto(base);
    await expect(page.getByRole('navigation', { name: 'Views' })).toBeVisible();
    if (redact) await expect(page.getByText(/redacted/).first()).toBeVisible();
    const analysis = JSON.parse((await page.locator('#escalint-data').textContent()) ?? '{}') as {
      paths: { id: string; source: string }[];
    };
    const p = analysis.paths[0];
    const hashes = ['#/', '#/atlas', '#/findings', '#/exposure', '#/fix', '#/detect'];
    if (p) hashes.push(`#/path/${p.id}`, `#/reach/${p.source}`);
    for (const h of hashes) {
      await page.goto(base + h);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    }
    await page.goto(`${base}#/atlas`);
    await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 30_000 });
    const violations = await page.evaluate(() => (window as unknown as { __csp: string[] }).__csp);
    expect(violations).toEqual([]);
    expect(network).toEqual([]);
  });
}
