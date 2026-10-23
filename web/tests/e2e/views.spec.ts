import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { openView, views } from './fixtures';

for (const v of views()) {
  for (const scheme of ['light', 'dark'] as const) {
    test(`${v.name} (${scheme}) renders and has no accessibility violations`, async ({
      page,
      browserName,
    }) => {
      const external: string[] = [];
      page.on('request', (r) => {
        if (!r.url().startsWith('http://127.0.0.1:')) external.push(r.url());
      });
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
      await openView(page, v.hash, v.body);
      await expect(page.getByRole('heading', { level: 1, name: v.heading })).toBeVisible();
      expect(external).toEqual([]);
      // axe once per view and theme, in Chromium (the rules do not depend on the engine).
      test.skip(browserName !== 'chromium', 'axe runs in Chromium only');
      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze();
      const summary = results.violations.map(
        (x) =>
          `${x.id}: ${x.nodes
            .map((n) => n.target.join(' '))
            .slice(0, 3)
            .join(' | ')}`,
      );
      expect(summary).toEqual([]);
    });
  }
}

test('trace: keyboard reaches the policy explainer', async ({ page }) => {
  const trace = views().find((v) => v.name === 'trace');
  if (!trace) throw new Error('no trace');
  await openView(page, trace.hash);
  const edge = page.getByRole('button', { name: /edge: .*policy explainer/ }).first();
  await edge.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('region', { name: 'Policy explainer' })).toBeVisible();
  await expect(page).toHaveURL(/sel=e_/);
});

test('findings: filters live in the URL and survive a reload', async ({ page }) => {
  await openView(page, '#/findings');
  await page.getByRole('checkbox', { name: 'critical' }).check();
  await expect(page).toHaveURL(/sev=critical/);
  await page.reload();
  await expect(page.getByRole('checkbox', { name: 'critical' })).toBeChecked();
});
