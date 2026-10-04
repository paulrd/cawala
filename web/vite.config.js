import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// base: './' — relative base so the static build works when served under the
// GitHub Pages repo subpath (/cawala/). The wasm-bindgen glue (--target web)
// loads its _bg.wasm via `new URL('..._bg.wasm', import.meta.url)`; with a
// relative base Vite rewrites that to a working relative asset URL and emits
// the wasm file into dist/ as an asset.
export default defineConfig({
  base: './',
  plugins: [svelte()],
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
