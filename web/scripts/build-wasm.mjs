#!/usr/bin/env node
// Builds the cawala-client wasm crate and runs wasm-bindgen to emit the JS
// glue + wasm into web/src/wasm.
//
// Robust against the current working directory: this script is invoked from
// web/ (npm scripts), but cargo must run from the workspace root. Both are
// resolved explicitly here.
//
//   cargo build --target wasm32-unknown-unknown -p cawala-client
//     CARGO_TARGET_DIR=web/.cargo-target   (keeps wasm artifacts out of root target/)
//   wasm-bindgen web/.cargo-target/wasm32-unknown-unknown/debug/cawala_client.wasm \
//     --out-dir web/src/wasm --weak-refs --target web
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..'); // web/
const rootDir = path.resolve(webDir, '..'); // workspace root
const targetDir = path.join(webDir, '.cargo-target');
const wasmFile = path.join(
  targetDir,
  'wasm32-unknown-unknown',
  'debug',
  'cawala_client.wasm',
);
const outDir = path.join(webDir, 'src', 'wasm');

function run(cmd, args, env = {}) {
  console.log(`\n$ ${cmd} ${args.join(' ')}`);
  execFileSync(cmd, args, {
    cwd: rootDir,
    env: { ...process.env, ...env },
    stdio: 'inherit',
  });
}

mkdirSync(outDir, { recursive: true });

run(
  'cargo',
  ['build', '--target', 'wasm32-unknown-unknown', '-p', 'cawala-client'],
  { CARGO_TARGET_DIR: targetDir },
);

run('wasm-bindgen', [
  wasmFile,
  '--out-dir',
  outDir,
  '--weak-refs',
  '--target',
  'web',
]);

console.log(`\nwasm glue emitted to ${path.relative(rootDir, outDir)}`);
