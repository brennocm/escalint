import { defineConfig, devices } from '@playwright/test';

// Hostile fixture against the real binary (needs bin/escalint with the UI).
export default defineConfig({
  testDir: 'tests/security',
  timeout: 120_000,
  reporter: 'list',
  use: { ...devices['Desktop Chrome'] },
});
