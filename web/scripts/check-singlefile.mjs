#!/usr/bin/env node
// Self-containment check for the single-file artifact (dist-single/index.html).
//
// Proves the R2 packaged artifact can run from `file://`:
//   - exactly one file is emitted (index.html);
//   - the document references no external JS/CSS/wasm/manifest asset (no
//     `src=`/`href=` file refs, no <script src>, no <link>);
//   - the wasm is not fetched by URL (no `..._bg.wasm` / default module path);
//   - the wasm bytes are embedded (base64 of the wasm magic `\0asm`).
//
// Wired into `npm run build:singlefile` so the evidence is regenerated on every
// build; run directly with `node scripts/check-singlefile.mjs`.
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = path.join(root, 'dist-single');
const htmlPath = path.join(dir, 'index.html');

let failures = 0;
function check(name, ok, detail = '') {
  const status = ok ? 'ok  ' : 'FAIL';
  console.log(`[singlefile] ${status} ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
}

const html = readFileSync(htmlPath, 'utf8');

// 1. Exactly one emitted file.
const emitted = readdirSync(dir);
check(
  'dist-single contains only index.html',
  emitted.length === 1 && emitted[0] === 'index.html',
  emitted.join(', '),
);

// Inspect the document markup only: strip the inlined script/style bodies, whose
// JS contains Svelte template strings with HTML-like `href="#..."` fragments.
const markup = html
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '<script></script>')
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '<style></style>');

// 2. No external asset tags: <script src>, <link>, <img src>, etc.
const scriptSrc = markup.match(/<script\b[^>]*\bsrc\s*=/gi) ?? [];
check('no <script src=...>', scriptSrc.length === 0, scriptSrc.join(', '));

const linkTags = markup.match(/<link\b[^>]*>/gi) ?? [];
check('no <link> tags (manifest/CSS)', linkTags.length === 0, linkTags.join(', '));

const assetAttrs =
  markup.match(
    /<(img|source|video|audio|iframe|embed|object|track)\b[^>]*\bsrc\s*=/gi,
  ) ?? [];
check('no external media/iframe src', assetAttrs.length === 0, assetAttrs.join(', '));

// 3. No non-anchor / non-data src or href attribute in the markup.
const urlAttrs = [
  ...markup.matchAll(/\b(?:src|href)\s*=\s*["']([^"']*)["']/gi),
].map((m) => m[1]);
const external = urlAttrs.filter((u) => !u.startsWith('#') && !u.startsWith('data:'));
check('no external src=/href= asset refs', external.length === 0, external.join(', '));

// 4. Wasm is never fetched by URL (default module path omitted at build time).
check(
  'no wasm module URL reference',
  !/cawala_client_bg\.wasm/.test(html),
);
check(
  'no default-module-path new URL fetch',
  !/new URL\(\s*[`'"]cawala_client_bg[^`'"]*\.wasm/.test(html),
);
check(
  'default module path omitted from glue',
  !/module_or_path\s*=\s*new URL/.test(html),
);

// 5. Bytes are embedded (base64 of the wasm magic `\0asm`).
check('embedded wasm bytes present (magic AGFzbQ)', /AGFzbQ/.test(html));

// 6. No surviving separate chunk import.
check('no dynamic-import chunk reference', !/import\s*\(\s*["'`][^"'`]*\.js["'`]/.test(html));

// 7. wasm-unsafe-eval CSP present (needed to compile wasm under a CSP).
check(
  "CSP allows 'wasm-unsafe-eval'",
  /Content-Security-Policy/.test(html) && /wasm-unsafe-eval/.test(html),
);

if (failures > 0) {
  console.error(`\n[singlefile] FAILED: ${failures} check(s) failed`);
  process.exit(1);
}
console.log('\n[singlefile] PASS: artifact is self-contained');
