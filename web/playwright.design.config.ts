import { defineConfig, devices } from '@playwright/test';

// Captures the #/design route (dev server only) for the Phase 1D checkpoint.
const port = 5174;

export default defineConfig({
  testDir: 'tests/design',
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${String(port)}`,
    ...devices['Desktop Chrome'],
    viewport: { width: 1280, height: 900 },
    deviceScaleFactor: 2,
    reducedMotion: 'reduce',
  },
  webServer: {
    command: `pnpm dev --host 127.0.0.1 --port ${String(port)} --strictPort`,
    url: `http://127.0.0.1:${String(port)}`,
    reuseExistingServer: !process.env.CI,
  },
});
