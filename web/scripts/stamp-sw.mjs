// Stamp the service-worker build id after `vite build`.
//
// web/public/sw.js ships with a literal `__BUILD_ID__` placeholder; this script
// replaces it in dist/sw.js with a per-deploy id so the browser installs a new
// worker (and a new cache) on every release. Run via the `build` npm script.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const swPath = join(root, 'dist', 'sw.js');

if (!existsSync(swPath)) {
  console.error(`stamp-sw: ${swPath} not found; run this after \`vite build\``);
  process.exit(1);
}

const buildId =
  (process.env.GITHUB_SHA || process.env.SOURCE_VERSION || '').slice(0, 12) ||
  process.env.npm_package_version ||
  String(Date.now());

const source = readFileSync(swPath, 'utf8');
if (!source.includes('__BUILD_ID__')) {
  console.warn('stamp-sw: __BUILD_ID__ placeholder not found; leaving sw.js unchanged');
  process.exit(0);
}

writeFileSync(swPath, source.replaceAll('__BUILD_ID__', buildId));
console.log(`stamp-sw: stamped dist/sw.js with build id ${buildId}`);
