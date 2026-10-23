import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  // Relative asset URLs so the same build works from `escalint serve`,
  // GitHub Pages (sub-path) and file:// in the HTML report.
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: 'happy-dom',
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/main.tsx', 'src/contract/**'],
      reporter: ['text', 'html', 'json-summary'],
    },
  },
});
