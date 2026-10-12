import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { viteSingleFile } from 'vite-plugin-singlefile';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = path.join(__dirname, 'src', 'wasm', 'cawala_client_bg.wasm');

const VIRTUAL_WASM_BYTES = 'virtual:cawala-wasm-bytes';
const RESOLVED_WASM_BYTES = '\0' + VIRTUAL_WASM_BYTES;

// CSP for the single-file artifact. `file://` blocks wasm compilation unless
// `'wasm-unsafe-eval'` is allowed; the other directives are kept permissive so
// the app's relay connections, blob workers and inline bundle keep working.
// Degradation is graceful: this never hard-fails the app.
const CSP = [
  "default-src 'self' data: blob:",
  "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' blob:",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src *",
  "worker-src 'self' blob:",
  "manifest-src 'self' data:",
].join('; ');

/**
 * Exposes the release wasm bytes as a base64 string through a virtual module,
 * so the single-file bundle can initialize wasm from bytes instead of fetching
 * the default module URL (which fails on `file://`).
 */
function wasmInlineBytes() {
  let base64 = null;
  return {
    name: 'cawala-wasm-inline-bytes',
    resolveId(id) {
      if (id === VIRTUAL_WASM_BYTES) return RESOLVED_WASM_BYTES;
      return null;
    },
    load(id) {
      if (id !== RESOLVED_WASM_BYTES) return null;
      if (base64 === null) {
        try {
          base64 = readFileSync(wasmPath).toString('base64');
        } catch {
          throw new Error(
            `single-file build: ${wasmPath} not found; run \`npm run build:wasm:release\` first`,
          );
        }
      }
      return `export default ${JSON.stringify(base64)};`;
    },
  };
}

/**
 * Drops the PWA manifest link (an external request that has no meaning in a
 * single self-contained file) and injects the wasm CSP meta tag.
 */
function singleFileHtml() {
  return {
    name: 'cawala-singlefile-html',
    transformIndexHtml(html) {
      let out = html.replace(
        /\s*<link[^>]*\brel=["']manifest["'][^>]*>\s*/i,
        '\n',
      );
      out = out.replace(
        '</head>',
        `    <meta http-equiv="Content-Security-Policy" content="${CSP}" />\n  </head>`,
      );
      return out;
    },
  };
}

// Single-file build: ONE self-contained dist-single/index.html. All JS, CSS and
// the wasm bytes are inlined; there are no `src=`/`href=` asset references and
// no dynamic-import chunks. The wasm is initialized from embedded bytes via the
// `inlineInit.js` seam (aliased as `cawala-wasm-init`).
export default defineConfig({
  base: './',
  // No public/ assets (manifest, sw.js) are emitted: they would be external
  // files. On `file://` the service worker is skipped and the manifest is gone.
  publicDir: false,
  plugins: [
    wasmInlineBytes(),
    singleFileHtml(),
    svelte(),
    viteSingleFile({ removeViteModuleLoader: true }),
  ],
  resolve: {
    alias: {
      'cawala-wasm-init': path.resolve(
        __dirname,
        'src',
        'lib',
        'wasm',
        'inlineInit.js',
      ),
    },
  },
  build: {
    target: 'es2022',
    outDir: 'dist-single',
  },
});
