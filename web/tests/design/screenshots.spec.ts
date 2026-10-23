import { expect, test } from '@playwright/test';

const outDir = process.env.SCREENSHOT_DIR ?? 'test-results/design';

for (const colorScheme of ['light', 'dark'] as const) {
  test(`design route renders in ${colorScheme} without external requests`, async ({ page }) => {
    const external: string[] = [];
    page.on('request', (request) => {
      if (!request.url().startsWith('http://127.0.0.1:')) {
        external.push(request.url());
      }
    });
    await page.emulateMedia({ colorScheme, reducedMotion: 'reduce' });
    await page.goto('/#/design');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('escalint · visual language');
    await expect(page.locator('html')).toHaveAttribute('data-theme', colorScheme);
    await page.evaluate(async () => {
      await document.fonts.ready;
    });
    expect(await page.evaluate(() => document.fonts.check('16px Inter'))).toBe(true);

    await page.screenshot({ path: `${outDir}/design-${colorScheme}.png`, fullPage: true });
    for (const id of ['sec-overview', 'sec-trace', 'sec-reach', 'sec-exposure']) {
      await page
        .locator(`section[aria-labelledby="${id}"]`)
        .screenshot({ path: `${outDir}/${id.replace('sec-', '')}-${colorScheme}.png` });
    }
    expect(external).toEqual([]);
  });
}
