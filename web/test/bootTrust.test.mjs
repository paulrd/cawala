import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Real boot-path trust tests (P1-F).
 *
 * Unlike `apiGetters.test.mjs` (which installs a fake client via
 * `__setClientForTest` and never spawns), these drive the actual
 * `_spawnRealNode` boot path through `__bootRealNodeForTest` with an injected
 * fake wasm module. They pin the fail-closed trust rule and the pin-preserving
 * behavior added in P1-F:
 *
 *   - a corrupt / version-bumped ledger blob must NOT establish trust, and
 *   - its original bytes must be preserved (never clobbered by a re-export).
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

const { __bootRealNodeForTest, isTrustEstablished, getTrustState } = await import(
  '../src/lib/api.js'
);

const NODE_ID = 'boot-node';
const IDENTITY_KEY = 'cawala.identity.v1';
const LEDGER_KEY = `cawala.ledger.v1:${NODE_ID}`;
const LEDGER_BACKUP_KEY = `cawala.ledger.backup.v1:${NODE_ID}`;

/** Pre-seed a 32-byte identity so boot never calls the wasm RNG. */
function seedIdentity() {
  memory.setItem(IDENTITY_KEY, 'ab'.repeat(32));
}

/**
 * A fake wasm module + node, faithful enough to run `_spawnRealNode`:
 * anchors live in the node only once `import_ledger_state` succeeds (mirroring
 * a real wasm client starting from empty local state).
 *
 * @param {{ onImportLedger?: (bytes: Uint8Array) => void, pinnedLedger?: string|null, leafPins?: Array<{nodeId: string, ledger: string}> }} [opts]
 */
function makeBootWasm(opts = {}) {
  const { onImportLedger, pinnedLedger = 'pl'.repeat(32), leafPins = [] } = opts;
  const flags = { ledgerImported: false };
  const node = {
    endpoint_id: () => NODE_ID,
    import_state() {},
    import_ledger_state(bytes) {
      if (onImportLedger) onImportLedger(bytes);
      // Reached only when the (possibly throwing) import succeeded.
      flags.ledgerImported = true;
    },
    export_state: () => new Uint8Array([1]),
    export_ledger_state: () => new Uint8Array([2]),
    ledger_status: () => ({
      address: null,
      parent: null,
      balance: null,
      height: null,
      pinned_ledger: flags.ledgerImported ? pinnedLedger : null,
      state_root: null,
      pending: 0,
      activity: 0,
      free() {},
    }),
    pending_orders: () => [],
    pinned_leaf_keys: () =>
      flags.ledgerImported
        ? leafPins.map((p) => ({ node_id: p.nodeId, ledger: p.ledger, free() {} }))
        : [],
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
    free() {},
  };
  const wasm = {
    ClientNode: { spawn_control: async () => node },
    generate_secret_key: () => new Uint8Array(32),
  };
  return { wasm, node, flags };
}

/** Boot with the given raw ledger bytes seeded under the scoped key. */
async function bootWithLedgerBytes(bytes, opts = {}) {
  seedIdentity();
  // Each boot starts without a quarantine backup so a test can assert whether
  // *this* boot wrote one.
  memory.removeItem(LEDGER_BACKUP_KEY);
  const b64 = Buffer.from(bytes).toString('base64');
  memory.setItem(LEDGER_KEY, b64);
  const { wasm } = makeBootWasm(opts);
  const { stop } = await __bootRealNodeForTest(wasm);
  return { stop, seededB64: b64 };
}

test('boot: a corrupt ledger blob is fail-closed and its bytes are preserved', async () => {
  const corrupt = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const { stop, seededB64 } = await bootWithLedgerBytes(corrupt, {
    onImportLedger() {
      throw new Error('malformed postcard');
    },
  });
  try {
    assert.equal(isTrustEstablished(), false, 'corrupt blob must not establish trust');
    const trust = getTrustState();
    assert.equal(trust.established, false);
    assert.equal(trust.needsReestablish, true);
    assert.equal(trust.ledgerBlobUnreadable, true, 'the unreadable blob is surfaced');
    // The original (unreadable) bytes are quarantined under the authoritative-
    // local backup key, so they survive the fresh export that overwrites the
    // live blob.
    assert.equal(memory.getItem(LEDGER_BACKUP_KEY), seededB64, 'corrupt blob is quarantined');
    assert.equal(
      memory.getItem(LEDGER_KEY),
      Buffer.from(new Uint8Array([2])).toString('base64'),
      'the live blob is a fresh export; the backup is the recovery copy',
    );
  } finally {
    stop();
  }
});

test('boot: a version-bumped ledger blob is fail-closed and its bytes are preserved', async () => {
  // A blob from a newer client version: decodes as bytes but the wasm
  // `import_ledger_state` rejects the unknown version.
  const bumped = new Uint8Array([0x04, 0x01, 0x02, 0x03]);
  const { stop, seededB64 } = await bootWithLedgerBytes(bumped, {
    onImportLedger() {
      throw new Error('unsupported ledger blob version');
    },
  });
  try {
    assert.equal(isTrustEstablished(), false, 'version-bumped blob must not establish trust');
    const trust = getTrustState();
    assert.equal(trust.established, false);
    assert.equal(trust.needsReestablish, true);
    assert.equal(trust.ledgerBlobUnreadable, true);
    assert.equal(memory.getItem(LEDGER_BACKUP_KEY), seededB64, 'version-bumped blob is quarantined');
    assert.equal(
      memory.getItem(LEDGER_KEY),
      Buffer.from(new Uint8Array([2])).toString('base64'),
    );
  } finally {
    stop();
  }
});

test('boot: a clean import with restored anchors establishes trust and persists', async () => {
  const { stop } = await bootWithLedgerBytes(new Uint8Array([0x03, 0x00]), {
    pinnedLedger: 'pl'.repeat(32),
  });
  try {
    assert.equal(isTrustEstablished(), true, 'imported anchors must establish trust');
    const trust = getTrustState();
    assert.equal(trust.established, true);
    assert.equal(trust.needsReestablish, false);
    assert.equal(trust.ledgerBlobUnreadable, false, 'a clean import has nothing to quarantine');
    // A successful import may safely re-export over the source blob.
    assert.equal(memory.getItem(LEDGER_KEY), Buffer.from(new Uint8Array([2])).toString('base64'));
    assert.equal(memory.getItem(LEDGER_BACKUP_KEY), null, 'no backup is written on a clean import');
  } finally {
    stop();
  }
});

test('boot: a clean import with no anchors is fail-closed', async () => {
  // Import succeeds, but the blob carried no pin: trust must still be false.
  const { stop } = await bootWithLedgerBytes(new Uint8Array([0x03, 0x00]), {
    pinnedLedger: null,
    leafPins: [],
  });
  try {
    assert.equal(isTrustEstablished(), false, 'no restored anchor means no trust');
    const trust = getTrustState();
    assert.equal(trust.established, false);
    assert.equal(trust.needsReestablish, true);
  } finally {
    stop();
  }
});
