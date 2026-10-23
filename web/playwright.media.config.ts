import { defineConfig, devices } from '@playwright/test';

// README media (make demo-video): the UI walkthrough video and one screenshot
// per view and theme, recorded from the production build on the vulnerable
// example. Not a test suite: it writes into ../docs/media.
const port = 4177;

export default defineConfig({
  testDir: 'tests/media',
  timeout: 180_000,
  reporter: 'list',
  workers: 1,
  use: {
    baseURL: `http://127.0.0.1:${String(port)}`,
    ...devices['Desktop Chrome'],
    viewport: { width: 1280, height: 720 },
    deviceScaleFactor: 1,
  },
  webServer: {
    command: `pnpm preview --host 127.0.0.1 --port ${String(port)} --strictPort`,
    url: `http://127.0.0.1:${String(port)}`,
    reuseExistingServer: !process.env.CI,
  },
});
