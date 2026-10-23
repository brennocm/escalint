import { expect, test } from '@playwright/test';
import { openView, views } from '../e2e/fixtures';

// Visual baselines (ADR 0019): Chromium, fixed viewport, reduced motion,
// both themes. The WebGL canvas of the Atlas is masked: software rendering
// differs between machines; its overlay (labels, areas) is compared.
for (const v of views()) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`${v.name}-${scheme}`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await openView(page, v.hash, v.body);
      await expect(page.getByRole('heading', { level: 1, name: v.heading })).toBeVisible();
      if (v.name === 'atlas')
        await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 15_000 });
      await page.evaluate(() => document.fonts.ready);
      await expect(page).toHaveScreenshot(`${v.name}-${scheme}.png`, {
        fullPage: false,
        mask: [page.locator('.atlas__gl')],
        maxDiffPixelRatio: 0.02,
        animations: 'disabled',
      });
    });
  }
}
