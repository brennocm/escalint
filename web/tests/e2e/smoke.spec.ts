import { readFileSync } from 'node:fs';
import { expect, test, type Page } from '@playwright/test';

const fixture = readFileSync(
  new URL('../../src/data/fixtures/vulnerable.analysis.json', import.meta.url),
  'utf8',
);

/** Serves the fixture as analysis.json and records requests leaving the origin. */
async function open(page: Page, hash = ''): Promise<string[]> {
  const external: string[] = [];
  page.on('request', (request) => {
    if (!request.url().startsWith('http://127.0.0.1:')) external.push(request.url());
  });
  await page.route('**/analysis.json', (route) =>
    route.fulfill({ contentType: 'application/json', body: fixture }),
  );
  await page.goto(`/${hash}`);
  return external;
}

test('loads the analysis with the theme applied and no external requests', async ({ page }) => {
  const external = await open(page);
  await expect(page.getByRole('navigation', { name: 'Views' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', /^(light|dark)$/);
  expect(external).toEqual([]);
});

test('navigates with links, the palette and the keyboard', async ({ page }) => {
  await open(page);
  await page.getByRole('link', { name: 'Findings' }).click();
  await expect(page).toHaveURL(/#\/findings$/);
  await page.keyboard.press('Control+k');
  await page.getByRole('dialog', { name: 'Search' }).getByRole('combobox').fill('atlas');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/#\/atlas$/);
  await page.keyboard.press('?');
  await expect(page.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/#\/findings$/);
});

test('invalid links degrade to the overview with a notice', async ({ page }) => {
  await open(page, '#/path/not-an-id');
  await expect(page.getByRole('status').filter({ hasText: 'invalid link' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Overview' })).toHaveAttribute(
    'aria-current',
    'page',
  );
});

test('shows a clear error for unsupported data', async ({ page }) => {
  await page.route('**/analysis.json', (route) =>
    route.fulfill({ contentType: 'application/json', body: '{"schema_version":"9"}' }),
  );
  await page.goto('/');
  await expect(page.getByRole('alert')).toContainText('unsupported schema_version');
});
