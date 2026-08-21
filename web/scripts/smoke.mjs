// M0 smoke test: drive the wasm client from Node against a live Rust node.
// Usage: node scripts/smoke.mjs [target-endpoint-id] [payload]
//
// The first argument is the EndpointId of a running `cargo run -p cawala-node`.
// If omitted, the script only proves the wasm endpoint can spawn and register
// on the relay.
import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

import init, { ClientNode } from "../src/wasm/cawala_client.js";

const wasmBytes = await readFile(new URL("../src/wasm/cawala_client_bg.wasm", import.meta.url));
await init(wasmBytes);
console.log("[smoke] wasm initialized");

const node = await ClientNode.spawn();
console.log("[smoke] endpoint spawned, id =", node.endpoint_id());

const target = process.argv[2];
if (!target) {
  console.log("[smoke] no target given; spawn-only check done (exit 0)");
  process.exit(0);
}

const payload = process.argv[3] ?? "hello from wasm smoke test";
console.log(`[smoke] pinging ${target}`);
const t0 = performance.now();
let pong;
try {
  pong = await node.ping(target, payload);
} catch (err) {
  console.error(`[smoke] PING FAILED: ${err}`);
  console.error("[smoke] note: this sandbox blocks pkarr/DNS address lookup; a relay-hinted connect or a normal network is required.");
  process.exit(2);
}
const ms = (performance.now() - t0).toFixed(0);
console.log(`[smoke] pong received in ${ms}ms:`, JSON.stringify(pong));

if (pong !== payload) {
  console.error("[smoke] MISMATCH between payload and pong");
  process.exit(1);
}
console.log("[smoke] round-trip OK");
process.exit(0);
