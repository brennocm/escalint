import { mkdirSync } from 'node:fs';
import { expect, test, type Page } from '@playwright/test';
import { ids, openView, views, vulnerable } from '../e2e/fixtures';

// Media for the README (make demo-video). The data is the synthetic
// vulnerable example account; nothing leaves the preview server.
const media = new URL('../../../docs/media/', import.meta.url).pathname;
const size = { width: 1280, height: 720 };

async function settle(page: Page, ms: number): Promise<void> {
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(ms);
}

test('walkthrough video: Overview, Trace, policy explainer, Fix plan, Atlas', async ({
  browser,
}) => {
  mkdirSync(media, { recursive: true });
  const context = await browser.newContext({
    viewport: size,
    colorScheme: 'dark',
    recordVideo: { dir: `${media}.video`, size },
  });
  const page = await context.newPage();
  const { path } = ids();

  await openView(page, '#/', vulnerable);
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  await settle(page, 2500);

  // A critical path, step by step.
  await page.goto(`/#/path/${path}`);
  await expect(page.getByRole('heading', { level: 1, name: /^Trace/ })).toBeVisible();
  await settle(page, 2500);

  // Why the edge exists: the statement that allows it.
  await page
    .getByRole('button', { name: /edge: .*policy explainer/ })
    .first()
    .click();
  const explainer = page.getByRole('region', { name: 'Policy explainer' });
  await expect(explainer).toBeVisible();
  await settle(page, 1000);
  await explainer.evaluate((el) => {
    el.scrollIntoView({ block: 'start' });
  });
  await settle(page, 3500);

  // What to change first.
  await page.getByRole('link', { name: 'Fix plan' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Fix plan' })).toBeVisible();
  await settle(page, 2500);

  // The whole account, then focus on the most exposed principal.
  await page.getByRole('link', { name: 'Atlas' }).click();
  await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 30_000 });
  await settle(page, 2000);
  await page.getByText('Principals in view (table)').click();
  await page.locator('.atlas__table tbody button', { hasText: 'pe021-attacker' }).click();
  await page.getByText('Principals in view (table)').click();
  await page.evaluate(() => {
    window.scrollTo(0, 0);
  });
  await settle(page, 3500);

  const video = page.video();
  await context.close();
  if (!video) throw new Error('no video recorded');
  await video.saveAs(`${media}ui.webm`);
  await video.delete();
});

test('one screenshot per view and theme', async ({ page }) => {
  mkdirSync(`${media}views`, { recursive: true });
  await page.setViewportSize({ width: 1280, height: 800 });
  for (const v of views()) {
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      // A hash change alone would not reload analysis.json (the Diff view
      // has its own document): start each view from a blank page.
      await page.unrouteAll();
      await page.goto('about:blank');
      await openView(page, v.hash, v.body);
      await expect(page.getByRole('heading', { level: 1, name: v.heading })).toBeVisible();
      if (v.name === 'atlas')
        await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 30_000 });
      await settle(page, 500);
      await page.screenshot({ path: `${media}views/${v.name}-${scheme}.png` });
    }
  }
});
