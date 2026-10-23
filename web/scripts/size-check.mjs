// Bundle budget (docs/benchmarks.md): the JavaScript the first page needs,
// gzip-compressed, must stay under 300 KB; views load on demand.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

const dist = process.argv[2] ?? 'dist';
const budget = 300 * 1024;
const html = readFileSync(join(dist, 'index.html'), 'utf8');
const entries = [...html.matchAll(/<script[^>]+src="\.?\/?([^"]+\.js)"/g)].map((m) => m[1]);
const preloads = [
  ...html.matchAll(/<link[^>]+rel="modulepreload"[^>]+href="\.?\/?([^"]+\.js)"/g),
].map((m) => m[1]);
const initial = [...new Set([...entries, ...preloads])];
if (initial.length === 0) {
  console.error('size-check: no entry script found in index.html');
  process.exit(2);
}
let total = 0;
for (const file of initial) {
  const size = gzipSync(readFileSync(join(dist, file))).length;
  total += size;
  console.log(`${file}: ${(size / 1024).toFixed(1)} KB gzip`);
}
const lazy = readdirSync(join(dist, 'assets')).filter(
  (f) => f.endsWith('.js') && !initial.some((i) => i.endsWith(f)),
);
console.log(
  `initial JS: ${(total / 1024).toFixed(1)} KB gzip (budget ${String(budget / 1024)} KB); ${String(lazy.length)} lazy chunk(s)`,
);
if (total > budget) {
  console.error('size-check: initial JavaScript exceeds the budget');
  process.exit(1);
}
