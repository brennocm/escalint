import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

// Runs the real binary (`escalint serve`) and checks the UI works under the
// strict CSP, with the token flow and without requests leaving the origin.
const root = fileURLToPath(new URL('../../..', import.meta.url));
const bin = process.env.ESCALINT_BIN ?? `${root}bin/escalint`;
let server: ChildProcess | null = null;
let url = '';

test.beforeAll(async () => {
  server = spawn(
    bin,
    [
      'serve',
      `${root}examples/vulnerable-account/snapshot.json`,
      '--config-file',
      `${root}examples/vulnerable-account/.escalint.yaml`,
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );
  url = await new Promise<string>((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => {
      reject(new Error(`no URL from escalint serve: ${buf}`));
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

test('serves the UI with the token flow, the strict CSP and no violations', async ({
  page,
  request,
}) => {
  const violations: string[] = [];
  const external: string[] = [];
  page.on('console', (m) => {
    if (/Content Security Policy|Content-Security-Policy/i.test(m.text()))
      violations.push(m.text());
  });
  page.on('request', (r) => {
    if (!r.url().startsWith(new URL(url).origin)) external.push(r.url());
  });
  const bare = await request.get(new URL('/', url).toString());
  expect(bare.status()).toBe(401);
  await page.goto(url);
  await expect(page).not.toHaveURL(/token=/);
  const csp = await page.evaluate(async () =>
    (await fetch('/analysis.json')).headers.get('content-security-policy'),
  );
  expect(csp).toContain("default-src 'none'");
  for (const hash of ['#/', '#/atlas', '#/findings', '#/exposure', '#/fix', '#/detect']) {
    await page.goto(new URL(`/${hash}`, url).toString());
    await expect(page.getByRole('navigation', { name: 'Views' })).toBeVisible();
  }
  await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 15_000 });
  expect(violations).toEqual([]);
  expect(external).toEqual([]);
});
