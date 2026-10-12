#!/usr/bin/env node
// Builds the cawala-client wasm crate and runs wasm-bindgen to emit the JS
// glue + wasm into web/src/wasm.
//
// Usage:
//   node scripts/build-wasm.mjs            # debug profile (fast; dev)
//   node scripts/build-wasm.mjs --release  # optimized profile (shippable)
//
// Robust against the current working directory: this script is invoked from
// web/ (npm scripts), but cargo must run from the workspace root. Both are
// resolved explicitly here.
//
//   cargo build [--release] --target wasm32-unknown-unknown -p cawala-client
//     CARGO_TARGET_DIR=web/.cargo-target   (keeps wasm artifacts out of root target/)
//   wasm-bindgen web/.cargo-target/wasm32-unknown-unknown/{debug,release}/cawala_client.wasm \
//     --out-dir web/src/wasm --weak-refs --target web --omit-default-module-path
//
// `--omit-default-module-path` removes wasm-bindgen's default
// `new URL('..._bg.wasm', import.meta.url)` + fetch fallback. Every caller must
// therefore pass an explicit `module_or_path` to `init()`. The web app does so
// through the build-specific init seam (`cawala-wasm-init`): the served build
// passes the Vite-emitted asset URL; the single-file build passes the wasm
// bytes decoded from an inlined base64 blob. `file://` cannot fetch the module
// URL, which is why the single-file target must init from bytes.
import { execFileSync } from 'node:child_process';
import { mkdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..'); // web/
const rootDir = path.resolve(webDir, '..'); // workspace root
const targetDir = path.join(webDir, '.cargo-target');

const release = process.argv.includes('--release');
const profile = release ? 'release' : 'debug';

const wasmFile = path.join(
  targetDir,
  'wasm32-unknown-unknown',
  profile,
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

const cargoArgs = ['build', '--target', 'wasm32-unknown-unknown', '-p', 'cawala-client'];
if (release) cargoArgs.push('--release');

// Serialize the build: the workspace is OOM-sensitive and only one cargo
// process may run at a time.
run('cargo', cargoArgs, { CARGO_TARGET_DIR: targetDir, CARGO_BUILD_JOBS: '1' });

run('wasm-bindgen', [
  wasmFile,
  '--out-dir',
  outDir,
  '--weak-refs',
  '--target',
  'web',
  '--omit-default-module-path',
]);

const emitted = path.join(outDir, 'cawala_client_bg.wasm');
const emittedBytes = statSync(emitted).size;
const human = (n) => `${(n / 1024 / 1024).toFixed(2)} MB (${n} bytes)`;

console.log(`\nwasm glue emitted to ${path.relative(rootDir, outDir)} (${profile} profile)`);
console.log(`wasm size: ${human(emittedBytes)}`);
