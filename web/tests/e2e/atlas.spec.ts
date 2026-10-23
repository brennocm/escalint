import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

const fixture = readFileSync(
  new URL('../../src/data/fixtures/vulnerable.analysis.json', import.meta.url),
  'utf8',
);

test('the Atlas renders with WebGL, without console errors, and keeps the camera in the URL', async ({
  page,
}) => {
  const errors: string[] = [];
  const pageErrors: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  page.on('pageerror', (e) => {
    errors.push(e.message);
    pageErrors.push(e.message);
  });
  await page.route('**/analysis.json', (route) =>
    route.fulfill({ contentType: 'application/json', body: fixture }),
  );
  await page.goto('/#/atlas');
  const stage = page.getByRole('application');
  await expect(stage).toBeVisible();
  // Headless Firefox on GPU-less CI runners has no WebGL2: there the Atlas
  // must degrade to its notice and the accessible table instead.
  const hasWebGL2 = await page.evaluate(
    () => document.createElement('canvas').getContext('webgl2') !== null,
  );
  if (!hasWebGL2) {
    await expect(page.getByText(/needs WebGL2/)).toBeVisible();
    await expect(page.getByText('Principals in view (table)')).toBeVisible();
    expect(pageErrors).toEqual([]);
    return;
  }
  await expect(page.getByText(/needs WebGL2/)).toHaveCount(0);
  await expect(page.getByText(/Laying out/)).toHaveCount(0, { timeout: 15_000 });
  // The WebGL canvas has drawn something other than the background.
  const painted = await page.evaluate(() => {
    const c = document.querySelector<HTMLCanvasElement>('.atlas__gl');
    const gl = c?.getContext('webgl2', { preserveDrawingBuffer: true });
    if (!c || !gl) return -1;
    const px = new Uint8Array(c.width * c.height * 4);
    gl.readPixels(0, 0, c.width, c.height, gl.RGBA, gl.UNSIGNED_BYTE, px);
    const bg = [px[0], px[1], px[2]];
    let other = 0;
    for (let i = 0; i < px.length; i += 4 * 97)
      if (px[i] !== bg[0] || px[i + 1] !== bg[1] || px[i + 2] !== bg[2]) other++;
    return other;
  });
  expect(painted).not.toBe(-1);
  await stage.focus();
  await page.keyboard.press('+');
  await expect(page).toHaveURL(/cam=/);
  expect(errors).toEqual([]);
});
