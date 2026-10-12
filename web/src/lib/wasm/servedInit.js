// Init seam — SERVED build.
//
// Vite resolves `cawala-wasm-init` to this module for the normal multi-asset
// build (see vite.config.js). wasm-bindgen is compiled with
// `--omit-default-module-path`, so we hand it the Vite-emitted wasm asset URL
// explicitly; the glue `fetch`es it (valid on http/https/localhost).
import wasmUrl from '../../wasm/cawala_client_bg.wasm?url';

/**
 * Initialize the wasm-bindgen module from the served wasm asset URL.
 * @param {object} wasm the `cawala_client.js` module namespace
 */
export async function initWasm(wasm) {
  await wasm.default({ module_or_path: wasmUrl });
}
