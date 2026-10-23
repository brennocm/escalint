import { defineConfig, devices } from '@playwright/test';

// The Pages demo build (web/dist-demo, produced by `make demo`).
const port = 4176;

export default defineConfig({
  testDir: 'tests/demo',
  timeout: 120_000,
  reporter: 'list',
  use: { baseURL: `http://127.0.0.1:${String(port)}`, ...devices['Desktop Chrome'] },
  webServer: {
    command: `pnpm exec vite preview --outDir dist-demo --host 127.0.0.1 --port ${String(port)} --strictPort`,
    url: `http://127.0.0.1:${String(port)}`,
    reuseExistingServer: !process.env.CI,
  },
});
