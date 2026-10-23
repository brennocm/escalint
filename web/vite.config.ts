import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// Modes:
// - default: the app served by `escalint serve` and the demo (lazy chunks, worker).
// - report: one JavaScript file with fonts inlined into the CSS, for the
//   single-file HTML report (`escalint report --html`, ADR 0018). The Go side
//   inlines it with the data and a hash-based CSP.
export default defineConfig(({ mode }) => {
  const report = mode === 'report';
  return {
    plugins: [react()],
    // Relative asset URLs so the same build works from `escalint serve`,
    // GitHub Pages (sub-path) and file://.
    base: './',
    define: report ? { 'import.meta.env.VITE_REPORT': JSON.stringify('true') } : {},
    build: report
      ? {
          outDir: 'dist/report',
          emptyOutDir: true,
          sourcemap: false,
          cssCodeSplit: false,
          modulePreload: false,
          assetsInlineLimit: 100_000_000,
          rolldownOptions: { output: { codeSplitting: false } },
        }
      : { outDir: 'dist', emptyOutDir: true, sourcemap: false },
    test: {
      environment: 'happy-dom',
      include: ['src/**/*.test.{ts,tsx}'],
      setupFiles: ['src/test-setup.ts'],
      coverage: {
        provider: 'v8',
        include: ['src/**/*.{ts,tsx}'],
        exclude: [
          'src/**/*.test.{ts,tsx}',
          'src/main.tsx',
          'src/test-setup.ts',
          'src/vite-env.d.ts',
          'src/contract/**',
          'src/workers/layout.worker.ts',
        ],
        reporter: ['text', 'html', 'json-summary'],
      },
    },
  };
});
