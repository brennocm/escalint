import { defineConfig, devices } from '@playwright/test';

// Performance budgets with synthetic data (docs/benchmarks.md).
const port = 4175;

export default defineConfig({
  testDir: 'tests/perf',
  timeout: 180_000,
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${String(port)}`,
    ...devices['Desktop Chrome'],
    viewport: { width: 1280, height: 800 },
  },
  webServer: {
    command: `pnpm preview --host 127.0.0.1 --port ${String(port)} --strictPort`,
    url: `http://127.0.0.1:${String(port)}`,
    reuseExistingServer: !process.env.CI,
  },
});
