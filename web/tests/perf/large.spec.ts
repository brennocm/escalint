import { rmSync, writeFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { syntheticAnalysis } from './synthetic';

// project.md §3.6: with 50,000 principals the Atlas stays usable through
// semantic zoom and says how it degrades. The ~100 MB document is served by
// the preview server from dist/ (route.fulfill cannot carry a body that
// large) and removed afterwards.
const data = 'dist/analysis.json';
test.beforeAll(() => {
  writeFileSync(data, syntheticAnalysis(50_000));
});
// dist/ is embedded in the binary: never leave the document there.
test.afterAll(() => {
  rmSync(data, { force: true });
});

test('50,000 principals: the browser keeps rendering frames and the Atlas explains its degradation', async ({
  page,
}) => {
  test.setTimeout(300_000);
  await page.goto('/#/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible({ timeout: 60_000 });
  await page.evaluate(() => {
    const w = window as unknown as { __gaps: number[]; __stop: boolean };
    w.__gaps = [];
    let last = performance.now();
    const tick = (now: number): void => {
      w.__gaps.push(now - last);
      last = now;
      if (!w.__stop) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  await page.goto('/#/atlas');
  await expect(page.getByText(/Large graph: 50,000 nodes/)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 240_000 });
  await page.goto('/#/exposure');
  await expect(page.getByRole('heading', { name: 'Exposure' })).toBeVisible();
  const gaps = await page.evaluate(() => {
    const w = window as unknown as { __gaps: number[]; __stop: boolean };
    w.__stop = true;
    return w.__gaps;
  });
  const longest = Math.max(...gaps);
  test.info().annotations.push({ type: 'longest-frame-gap-ms', description: longest.toFixed(0) });
  console.log(`longest frame gap ${longest.toFixed(0)} ms over ${String(gaps.length)} frames`);
  // The main thread may stall while building the scene, never for long.
  expect(longest).toBeLessThan(3000);
});
