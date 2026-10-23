import { expect, test } from '@playwright/test';

// The GitHub Pages demo (make demo): synthetic data, banner, dataset switch.
test('demo shows the synthetic-data banner and switches datasets', async ({ page }) => {
  const external: string[] = [];
  page.on('request', (r) => {
    if (!r.url().startsWith('http://127.0.0.1:')) external.push(r.url());
  });
  await page.goto('/');
  await expect(page.getByRole('note').filter({ hasText: 'synthetic data' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await page.getByRole('combobox', { name: 'Dataset' }).selectOption('synthetic-2k');
  await expect(page).toHaveURL(/dataset=synthetic-2k/);
  await expect(page.getByText(/2 account\(s\), \d+ nodes/)).toBeVisible({ timeout: 30_000 });
  await page.goto('/?dataset=synthetic-2k#/atlas');
  await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 60_000 });
  expect(external).toEqual([]);
});
