import { expect, test } from '@playwright/test';

test('home page renders with the theme applied and no external requests', async ({ page }) => {
  const external: string[] = [];
  page.on('request', (request) => {
    if (!request.url().startsWith('http://127.0.0.1:')) {
      external.push(request.url());
    }
  });

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('escalint');
  await expect(page.locator('html')).toHaveAttribute('data-theme', /^(light|dark)$/);
  expect(external).toEqual([]);
});
