// Init seam — SINGLE-FILE build.
//
// Vite resolves `cawala-wasm-init` to this module for the single-file build
// (see vite.config.singlefile.js). The wasm bytes are embedded at build time as
// a base64 string by the `cawala-wasm-bytes` plugin, so initialization never
// touches the network — `file://` blocks `fetch`/`instantiateStreaming` of the
// default `new URL('..._bg.wasm', import.meta.url)` module path.
import wasmB64 from 'virtual:cawala-wasm-bytes';

/** Decode a base64 string to bytes (atob is available on file:// and workers). */
function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Initialize the wasm-bindgen module from bytes embedded in the bundle.
 * @param {object} wasm the `cawala_client.js` module namespace
 */
export async function initWasm(wasm) {
  await wasm.default({ module_or_path: base64ToBytes(wasmB64) });
}
