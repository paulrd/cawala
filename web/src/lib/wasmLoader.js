// Isolated wasm-init seam.
//
// `cawala-wasm-init` is resolved by Vite to the build-specific module:
//   - served / dev  -> ./wasm/servedInit.js  (Vite-emitted wasm asset URL)
//   - single-file   -> ./wasm/inlineInit.js  (wasm bytes inlined as base64)
//
// The wasm-bindgen glue is imported statically here so the single-file build
// inlines it (and its embedded bytes) into the one HTML file with no separate
// dynamic-import chunk — `initApi` would otherwise fail on `file://`. This
// module is loaded via a dynamic import from `api.js` so that Node test runs
// (which run without a Vite alias resolver) never evaluate the bare
// `cawala-wasm-init` specifier.
import * as wasm from '../wasm/cawala_client.js';
import { initWasm } from 'cawala-wasm-init';

/**
 * Load and initialize the cawala wasm client using the build-appropriate
 * module source (asset URL for served, embedded bytes for single-file).
 * @returns {Promise<object>} the `cawala_client.js` module namespace
 */
export async function loadWasmClient() {
  await initWasm(wasm);
  return wasm;
}
