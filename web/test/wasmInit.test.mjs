import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

/**
 * Bytes-init smoke for the single-file / `file://` target (R2, spec §4).
 *
 * The single-file build inlines the wasm as base64 and initializes it from
 * in-memory bytes — never `instantiateStreaming` on `file://`. This test proves
 * the built glue's `init({ module_or_path: Uint8Array })` path actually
 * resolves and yields a live instance, so "init from bytes" rests on repeatable
 * evidence rather than on the spike. It imports the release glue directly
 * (no Vite alias, no `wasmLoader.js`), so it also stays runnable under plain
 * `node --test`.
 */

import init, * as wasm from '../src/wasm/cawala_client.js';

const WASM_PATH = fileURLToPath(
  new URL('../src/wasm/cawala_client_bg.wasm', import.meta.url),
);

test('release wasm glue initializes from in-memory bytes (file:// path)', async () => {
  const bytes = new Uint8Array(await readFile(WASM_PATH));
  assert.ok(bytes.byteLength > 0, 'wasm bytes were read from disk');

  const instance = await init({ module_or_path: bytes });
  assert.ok(
    instance && instance.memory instanceof WebAssembly.Memory,
    'init({ module_or_path }) resolves with an instantiated wasm module',
  );

  // The module-level bindings are live — proving the instance, not just the
  // promise, works. A random 32-byte secret exercises the getrandom js backend.
  assert.equal(typeof wasm.ClientNode, 'function');
  assert.equal(typeof wasm.UserIdentity, 'function');
  const secret = wasm.generate_secret_key();
  assert.ok(secret instanceof Uint8Array);
  assert.equal(secret.length, 32);
});
