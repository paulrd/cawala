import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Fresh-install transport activation tests (P2-F, Addendum C §11).
 *
 * The bug: on a fresh install `_loadOrCreateIdentity` generates a RANDOM
 * transport seed, and an in-session `createIdentity`/`restoreIdentity` only
 * persisted the mnemonic-derived seed "for the next load". A user who created
 * an identity and then joined in the same session joined under the random
 * NodeId; the next reload switched to the mnemonic-derived NodeId and orphaned
 * that join's `ChildEntry`/anchor.
 *
 * These tests drive the real boot + create path with an injected fake wasm
 * module and pin the fix:
 *   - create re-spawns the live node with the derived seed BEFORE join, and
 *   - if the re-spawn fails, `requestJoin` is gated (a reload is required)
 *     instead of silently joining on the stale NodeId.
 *
 * A separate file (not `userIdentity.test.mjs`) gives a clean module instance:
 * `node --test` runs each test file in its own process.
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

// ── Mock crypto backend (stands in for the wasm UserIdentity) ──────────────

async function _sha256Hex(text) {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)),
  );
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function _bytesFromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const mockBackend = {
  async deriveAddress(mnemonic, passphrase) {
    const hex = await _sha256Hex(`addr:${mnemonic}:${passphrase}`);
    return `0x${hex.slice(0, 40)}`;
  },
  async secretBytes(mnemonic, passphrase) {
    return (await _bytesFromHex(await _sha256Hex(`secret:${mnemonic}:${passphrase}`))).slice(0, 32);
  },
  async transportSeed(mnemonic, passphrase) {
    return (await _bytesFromHex(await _sha256Hex(`transport:${mnemonic}:${passphrase}`))).slice(0, 32);
  },
};

const { createIdentity, requestJoin, getEndpointId, __bootRealNodeForTest } = await import(
  '../src/lib/api.js'
);
const { STORAGE_KEYS } = await import('../src/lib/storage.js');
const { setIdentityBackend } = await import('../src/lib/userIdentity.js');

setIdentityBackend(mockBackend);

const RANDOM_SEED = Uint8Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff);

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * A fake wasm module + node faithful enough to run `_spawnRealNode`, joined as
 * a fresh install (no address). `spawn_control` records every seed it was
 * called with and tags each node's `endpoint_id` with that seed, so the test
 * can tell exactly which transport identity is live.
 *
 * @param {{ failOnSpawn?: number }} [opts] 1-based spawn call number to throw on.
 */
function makeActivationWasm(opts = {}) {
  const { failOnSpawn = null } = opts;
  const spawnSeeds = [];
  const joins = [];
  const registered = [];

  const nodeFor = (seed) => {
    const nodeId = `node-${hex(seed)}`;
    return {
      endpoint_id: () => nodeId,
      import_state() {},
      import_ledger_state() {},
      export_state: () => new Uint8Array([1]),
      export_ledger_state: () => new Uint8Array([2]),
      set_user_identity_from_secret() {},
      user_eth_address: () => '0x' + 'ab'.repeat(20),
      async register_eth_address() {
        registered.push(nodeId);
        return 'accepted';
      },
      ledger_status: () => ({
        address: null,
        parent: null,
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
        state: 'none',
        parent: null,
        slot: null,
        address: null,
        reason: null,
        reject_code: null,
        free() {},
      }),
      pending_join_outbound: () => null,
      local_snapshot: () => ({ parent: null, free() {} }),
      ledger_activity: () => [],
      settlement_records: () => [],
      async request_balance() {
        return 'delivered';
      },
      async join(parent) {
        joins.push({ nodeId, parent });
        return { status: 'pending', reason: null, reject_code: null, free() {} };
      },
      free() {},
    };
  };

  const wasm = {
    ClientNode: {
      spawn_control: async (seed) => {
        spawnSeeds.push(Uint8Array.from(seed));
        if (failOnSpawn != null && spawnSeeds.length === failOnSpawn) {
          throw new Error('spawn failed');
        }
        return nodeFor(seed);
      },
    },
    generate_secret_key: () => Uint8Array.from(RANDOM_SEED),
  };
  return { wasm, spawnSeeds, joins, registered };
}

test('fresh install: create re-spawns the live node with the derived seed before join', async () => {
  memory.clear();
  const { wasm, spawnSeeds, joins } = makeActivationWasm();

  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    // Pre-identity: the node runs the random startup seed.
    assert.equal(spawnSeeds.length, 1, 'boot spawned once');
    assert.equal(getEndpointId(), `node-${hex(RANDOM_SEED)}`);

    const { inputMnemonic } = await createIdentity();
    const derivedSeed = await mockBackend.transportSeed(inputMnemonic, '');
    const derivedHex = hex(derivedSeed);

    // The live node was torn down and re-spawned with the mnemonic-derived
    // seed, and its NodeId now matches the phrase.
    assert.equal(spawnSeeds.length, 2, 'create re-spawned the node');
    assert.equal(hex(spawnSeeds[1]), derivedHex, 're-spawn uses the derived seed');
    assert.equal(getEndpointId(), `node-${derivedHex}`, 'live NodeId is mnemonic-derived');
    assert.equal(
      memory.getItem(STORAGE_KEYS.IDENTITY),
      derivedHex,
      'persisted seed is the derived one',
    );

    // A same-session join now goes out under the derived NodeId, not the
    // pre-identity random one — so the reload cannot orphan it.
    const result = await requestJoin('parent-node');
    assert.equal(result.status, 'pending');
    assert.equal(joins.length, 1, 'join issued once');
    assert.equal(joins[0].nodeId, `node-${derivedHex}`, 'join used the derived NodeId');
    assert.notEqual(joins[0].nodeId, `node-${hex(RANDOM_SEED)}`, 'join is not on the stale NodeId');
  } finally {
    stop();
  }
});

test('fresh install: a failed re-spawn gates join instead of joining on the stale NodeId', async () => {
  memory.clear();
  const { wasm, spawnSeeds, joins } = makeActivationWasm({ failOnSpawn: 2 });

  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    assert.equal(spawnSeeds.length, 1, 'boot spawned once');

    // Creation succeeds (the identity record is persisted), but the re-spawn
    // fails, leaving the live transport on the old random seed.
    await createIdentity();
    assert.equal(spawnSeeds.length, 2, 're-spawn was attempted');

    // No join may proceed under the stale NodeId: the user must reload.
    await assert.rejects(
      () => requestJoin('parent-node'),
      /Reload the page before joining/,
      'join is gated while the node is on the stale seed',
    );
    assert.equal(joins.length, 0, 'no join reached the live node');
  } finally {
    stop();
  }
});
