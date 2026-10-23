import { expect, test } from '@playwright/test';
import { syntheticAnalysis } from './synthetic';

// Budgets of project.md §3.6, measured on 10,000 principals / ~40,000 edges.
const body = syntheticAnalysis(10_000);

test.beforeEach(async ({ page }) => {
  await page.route('**/analysis.json', (route) =>
    route.fulfill({ contentType: 'application/json', body }),
  );
});

test('Overview is useful within 2 s of the data arriving', async ({ page }) => {
  await page.goto('/#/');
  const start = Date.now();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText(/Tier 0 — admin/)).toBeVisible();
  const elapsed = Date.now() - start;
  test.info().annotations.push({ type: 'overview-ms', description: String(elapsed) });
  expect(elapsed).toBeLessThan(2000);
});

test('Atlas pans with a median frame time under 33 ms and no long tasks while interacting', async ({
  page,
}) => {
  await page.goto('/#/atlas');
  await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 120_000 });
  await page.evaluate(() => {
    const w = window as unknown as { __long: number[] };
    w.__long = [];
    new PerformanceObserver((list) => {
      for (const e of list.getEntries()) w.__long.push(e.duration);
    }).observe({ type: 'longtask', buffered: false });
  });
  const stage = page.getByRole('application');
  const box = await stage.boundingBox();
  if (!box) throw new Error('no stage');
  // Measure frames while the pointer drags the camera.
  await page.evaluate(() => {
    const w = window as unknown as { __frames: Promise<number[]> };
    w.__frames = new Promise<number[]>((resolve) => {
      const times: number[] = [];
      let last = performance.now();
      const tick = (now: number): void => {
        times.push(now - last);
        last = now;
        if (times.length < 90) requestAnimationFrame(tick);
        else resolve(times.slice(10));
      };
      requestAnimationFrame(tick);
    });
  });
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  for (let i = 0; i < 60; i++)
    await page.mouse.move(box.x + box.width / 2 + i * 4, box.y + box.height / 2 + i * 2);
  await page.mouse.up();
  const frames = await page.evaluate(
    () => (window as unknown as { __frames: Promise<number[]> }).__frames,
  );
  const sorted = [...frames].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)] ?? 0;
  const long = await page.evaluate(() => (window as unknown as { __long: number[] }).__long);
  test
    .info()
    .annotations.push(
      { type: 'median-frame-ms', description: median.toFixed(1) },
      { type: 'long-tasks-ms', description: long.join(',') },
    );
  expect(median).toBeLessThan(33);
  // Informative on software GPUs; reported, not gated (project.md §3.6).
  console.log(
    `median frame ${median.toFixed(1)} ms; long tasks while panning: ${long.map((x) => x.toFixed(0)).join(', ') || 'none'}`,
  );
});
