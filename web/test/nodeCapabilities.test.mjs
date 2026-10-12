import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * R1b node-client API capabilities handshake (F1).
 *
 * These drive the real boot path (`_spawnRealNode`) with an injected fake wasm
 * module so the handshake and its gating run exactly as at runtime:
 *   - a node advertising `NODE_FEATURE_ETH_IDENTITY` is fetched and published,
 *   - a node that is available but lacks the feature gates the ETH registration,
 *   - an unavailable handshake (old node / no method) keeps the legacy
 *     best-effort registration, so nothing regresses.
 *
 * `node --test` runs each file in its own process, so the module instance here
 * is isolated from the other api tests.
 */

class MemoryStorage {
  #map = new Map();
  getItem(key) {
    return this.#map.has(key) ? this.#map.get(key) : null;
  }
  setItem(key, value) {
    this.#map.set(key, String(value));
  }
  removeItem(key) {
    this.#map.delete(key);
  }
  clear() {
    this.#map.clear();
  }
}

const memory = new MemoryStorage();
globalThis.localStorage = memory;
globalThis.window = { localStorage: memory };
globalThis.$state = (value) => value;

const { __bootRealNodeForTest, getNodeCapabilities, getEthRegistrationStatus } = await import(
  '../src/lib/api.js'
);
const { apiCapabilities } = await import('../src/lib/stores.svelte.js');

const NODE_ID = 'caps-node';
const IDENTITY_KEY = 'cawala.identity.v1';

/** Pre-seed a 32-byte identity so boot never calls the wasm RNG. */
function seedIdentity() {
  memory.setItem(IDENTITY_KEY, 'ab'.repeat(32));
}

/** A fake wasm `NodeCapabilitiesDto`; `free()` records that it was released. */
function capsDto({ available = true, version = 1, features = 1, supports = true, freed } = {}) {
  return {
    available,
    client_api_version: version,
    features,
    supports_eth_identity: supports,
    free() {
      freed?.push('caps-dto');
    },
  };
}

/**
 * A fake wasm module + node faithful enough to run `_spawnRealNode` joined with
 * a user identity set, so the boot-time ETH registration path is exercised.
 *
 * @param {{ capabilities?: object, hasMethod?: boolean }} [opts]
 */
function makeCapsWasm(opts = {}) {
  const { capabilities = capsDto(), hasMethod = true } = opts;
  const registerCalls = [];
  const freed = [];
  const node = {
    endpoint_id: () => NODE_ID,
    import_state() {},
    import_ledger_state() {},
    export_state: () => new Uint8Array([1]),
    export_ledger_state: () => new Uint8Array([2]),
    ledger_status: () => ({
      address: '0.3.1',
      parent: 'parent-node',
      balance: null,
      height: null,
      pinned_ledger: null,
      state_root: null,
      pending: 0,
      activity: 0,
      free() {},
    }),
    pending_orders: () => [],
    pinned_leaf_keys: () => [],
    join_status: () => ({
      state: 'joined',
      parent: 'parent-node',
      slot: 2,
      address: '0.3.1',
      reason: null,
      reject_code: null,
      free() {},
    }),
    pending_join_outbound: () => null,
    local_snapshot: () => ({ parent: 'parent-node', free() {} }),
    ledger_activity: () => [],
    settlement_records: () => [],
    user_eth_address: () => '0x' + 'ab'.repeat(20),
    async register_eth_address() {
      registerCalls.push(NODE_ID);
      return 'accepted';
    },
    async request_balance() {
      return 'delivered';
    },
    free() {},
  };
  if (hasMethod) {
    node.node_capabilities = async () => {
      freed.push('caps');
      return capabilities;
    };
  }
  const wasm = {
    ClientNode: { spawn_control: async () => node },
    generate_secret_key: () => new Uint8Array(32),
  };
  return { wasm, registerCalls, freed };
}

/** Let the fire-and-forget boot registration settle. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

test('boot fetches capabilities and publishes the advertised version + feature', async () => {
  memory.clear();
  seedIdentity();
  const freed = [];
  const { wasm, registerCalls } = makeCapsWasm({
    capabilities: capsDto({ version: 2, features: 1, supports: true, freed }),
  });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    const caps = getNodeCapabilities();
    assert.ok(caps, 'a completed handshake is exposed');
    assert.equal(caps.available, true);
    assert.equal(caps.clientApiVersion, 2);
    assert.equal(caps.supportsEthIdentity, true);
    assert.equal(apiCapabilities.nodeCapabilitiesAvailable, true);
    assert.equal(apiCapabilities.nodeClientApiVersion, 2);
    assert.equal(apiCapabilities.nodeSupportsEthIdentity, true);
    assert.ok(freed.includes('caps-dto'), 'the wasm DTO is freed');

    await settle();
    assert.equal(registerCalls.length, 1, 'the feature-present node receives the registration');
  } finally {
    stop();
  }
});

test('an available node without the ETH feature gates the registration', async () => {
  memory.clear();
  seedIdentity();
  const { wasm, registerCalls } = makeCapsWasm({
    capabilities: capsDto({ version: 1, features: 0, supports: false }),
  });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    const caps = getNodeCapabilities();
    assert.ok(caps, 'the handshake is still available');
    assert.equal(caps.available, true);
    assert.equal(caps.supportsEthIdentity, false);
    assert.equal(apiCapabilities.nodeSupportsEthIdentity, false);

    await settle();
    assert.equal(registerCalls.length, 0, 'no variant-24 attempt without the feature');
    assert.equal(getEthRegistrationStatus().status, 'unsupported');
  } finally {
    stop();
  }
});

test('an unavailable handshake (old node) keeps the legacy best-effort registration', async () => {
  memory.clear();
  seedIdentity();
  // No `node_capabilities` method at all: this is a wasm build / node that
  // predates the handshake.
  const { wasm, registerCalls } = makeCapsWasm({ hasMethod: false });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    assert.equal(getNodeCapabilities(), null);
    assert.equal(apiCapabilities.nodeCapabilitiesAvailable, false);
    assert.equal(apiCapabilities.nodeClientApiVersion, null);
    assert.equal(apiCapabilities.nodeSupportsEthIdentity, false);

    await settle();
    assert.equal(
      registerCalls.length,
      1,
      'unavailable capabilities must not block the legacy registration',
    );
  } finally {
    stop();
  }
});

test('a node that reports "capabilities unavailable" is treated as old (legacy path)', async () => {
  memory.clear();
  seedIdentity();
  const { wasm, registerCalls } = makeCapsWasm({
    capabilities: capsDto({ available: false, supports: false }),
  });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    assert.equal(getNodeCapabilities(), null, 'a non-available DTO is not cached');
    assert.equal(apiCapabilities.nodeCapabilitiesAvailable, false);

    await settle();
    assert.equal(registerCalls.length, 1, 'legacy best-effort registration still runs');
  } finally {
    stop();
  }
});
