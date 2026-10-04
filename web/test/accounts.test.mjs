import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Accounts mapping / gating (P3).
 *
 * `api.js` imports the Svelte rune stores, so `$state` and localStorage are
 * shimmed before the module loads. The wasm layer is not exercised: these are
 * the pure helpers the wasm-reading path delegates to.
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

globalThis.localStorage = new MemoryStorage();
globalThis.$state = (value) => value;

const { mapAdminLedgerRows, canReadAdminLedger } = await import('../src/lib/api.js');

// ── canReadAdminLedger ───────────────────────────────────────────────────────

test('reading an administered ledger needs an administer-capable target', () => {
  assert.equal(canReadAdminLedger({ canAdminister: true }), true);
  assert.equal(canReadAdminLedger({ canAdminister: false }), false);
  assert.equal(canReadAdminLedger({ unlocked: true }), false);
  assert.equal(canReadAdminLedger({}), false);
  assert.equal(canReadAdminLedger(null), false);
  assert.equal(canReadAdminLedger(undefined), false);
});

// ── mapAdminLedgerRows ───────────────────────────────────────────────────────

function snapshot(overrides = {}) {
  return {
    parentBalance: 100,
    equity: -25,
    root: false,
    truncated: false,
    accounts: [
      { id: 'child-a', kind: 'node', slot: 1, address: '0.3.1', balance: 60 },
      { id: 'user-b', kind: 'user', slot: 5, address: '0.3.5', balance: 65 },
      { id: 'detached-c', kind: null, slot: null, address: null, balance: 0 },
    ],
    ...overrides,
  };
}

test('maps the parent asset, each liability, and the canonical equity row', () => {
  const rows = mapAdminLedgerRows(snapshot());
  assert.equal(rows.length, 5);
  assert.deepEqual(
    rows.map((row) => row.type),
    ['asset', 'liability', 'liability', 'liability', 'equity'],
  );

  assert.equal(rows[0].label, 'Account with parent');
  assert.equal(rows[0].balance, 100);

  assert.equal(rows[1].label, 'Account for 0.3.1');
  assert.equal(rows[1].kind, 'node');
  assert.equal(rows[1].address, '0.3.1');
  assert.equal(rows[1].balance, 60);

  assert.equal(rows[2].label, 'Account for 0.3.5');
  assert.equal(rows[2].kind, 'user');

  // A detached ledger account has no kind/slot/address but is still a row.
  assert.equal(rows[3].label, 'Account for detached-c');
  assert.equal(rows[3].kind, null);
  assert.equal(rows[3].address, null);
  assert.equal(rows[3].balance, 0);

  // Equity is the node's own figure, negative allowed, never re-derived here.
  assert.equal(rows[4].label, 'Node equity');
  assert.equal(rows[4].balance, -25);

  assert.equal(rows.truncated, false);
});

test('a root node labels its (normally zero) parent account as detached', () => {
  const rows = mapAdminLedgerRows(snapshot({ root: true, parentBalance: 0 }));
  assert.equal(rows[0].label, 'Detached parent balance');
  assert.equal(rows[0].balance, 0);
});

test('the truncated flag is carried on the mapped rows', () => {
  const rows = mapAdminLedgerRows(snapshot({ truncated: true }));
  assert.equal(rows.truncated, true);
  const untruncated = mapAdminLedgerRows(snapshot());
  assert.equal(untruncated.truncated, false);
});

test('a snapshot with no accounts still yields the asset and equity rows', () => {
  const rows = mapAdminLedgerRows(
    snapshot({ accounts: [], parentBalance: 0, equity: 0, root: true }),
  );
  assert.equal(rows.length, 2);
  assert.deepEqual(
    rows.map((row) => row.type),
    ['asset', 'equity'],
  );
});
