import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// base: './' — relative base so the static build works when served under the
// GitHub Pages repo subpath (/cawala/) or any other subpath. The wasm-bindgen
// glue is built with `--omit-default-module-path`, so the wasm module URL is
// supplied explicitly by the served init seam
// (`src/lib/wasm/servedInit.js`, aliased below as `cawala-wasm-init`). Vite
// emits the wasm file into dist/ as an asset; with a relative base the emitted
// asset URL resolves correctly under any served path.
export default defineConfig({
  base: './',
  plugins: [svelte()],
  resolve: {
    alias: {
      // Build-specific wasm init seam (see src/lib/wasmLoader.js).
      // Served/dev build initializes the module from its Vite asset URL;
      // the single-file config aliases the same specifier to the inline-bytes
      // seam (vite.config.singlefile.js).
      'cawala-wasm-init': path.resolve(__dirname, 'src/lib/wasm/servedInit.js'),
    },
  },
  server: {
    // `lib/adminPolicy.js` imports ../../../../ADMIN_POLICY.md?raw from the
    // repo root, which is outside this app's root: allow it in dev.
    fs: { allow: ['..'] },
  },
  build: {
    // wasm-bindgen glue + modern browser targets; nothing legacy required
    target: 'es2022',
  },
});
