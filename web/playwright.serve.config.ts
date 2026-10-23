import { defineConfig, devices } from '@playwright/test';

// `escalint serve` end to end: needs bin/escalint built with the UI
// (make web-build build), or ESCALINT_BIN.
export default defineConfig({
  testDir: 'tests/serve',
  timeout: 90_000,
  reporter: 'list',
  use: { ...devices['Desktop Chrome'] },
});
