// M0 browser-tab-to-browser-tab smoke test: in ONE Node process, spawn two
// wasm client endpoints ("tab A" and "tab B") and have A ping B. This proves
// a browser tab can both answer AND initiate pings over the N0 relay — the
// exact path that was broken before the accept loop was added to the wasm
// client.
//
// Usage: node scripts/smoke-tabs.mjs [payload]
//
// Exit codes: 0 = round-trip OK, 1 = payload mismatch, 2 = ping failure.
import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

import init, { ClientNode } from "../src/wasm/cawala_client.js";

const wasmBytes = await readFile(new URL("../src/wasm/cawala_client_bg.wasm", import.meta.url));
await init(wasmBytes);
console.log("[smoke-tabs] wasm initialized");

const tabA = await ClientNode.spawn();
console.log("[smoke-tabs] tab A spawned, id =", tabA.endpoint_id());
const tabB = await ClientNode.spawn();
console.log("[smoke-tabs] tab B spawned, id =", tabB.endpoint_id());

const payload = process.argv[2] ?? "hello from tab A to tab B";
console.log(`[smoke-tabs] A pinging B (${tabB.endpoint_id()})`);
const t0 = performance.now();
let pong;
try {
  pong = await tabA.ping(tabB.endpoint_id(), payload);
} catch (err) {
  console.error(`[smoke-tabs] PING FAILED: ${err}`);
  console.error("[smoke-tabs] note: a relay-hinted connect or a normal network is required if pkarr/DNS address lookup is blocked.");
  process.exit(2);
}
const ms = (performance.now() - t0).toFixed(0);
console.log(`[smoke-tabs] pong received in ${ms}ms:`, JSON.stringify(pong));

if (pong !== payload) {
  console.error("[smoke-tabs] MISMATCH between payload and pong");
  process.exit(1);
}
console.log("[smoke-tabs] round-trip OK");
process.exit(0);
