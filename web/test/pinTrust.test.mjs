import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * F6 — explicit leaf-key pin trust.
 *
 * The wasm client no longer counts a trust-on-first-use pin as established
 * trust: `getTrustState().established` is true only for a *confirmed* routing
 * pin with no pending change, a pin change is surfaced (never adopted), and
 * `confirmPin()` flips an unconfirmed pin to confirmed.
 *
 * A fake client implements the new `pin_status()` / `confirm_pin()` surface so
 * the api.js mapping, fail-closed rule and confirm action are exercised on
 * plain Node.
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

const { __setClientForTest, getTrustState, isTrustEstablished, confirmPin } = await import(
  '../src/lib/api.js'
);
// The reactive ledger store api.js mirrors `_trustEstablished` into. Imported
// after the rune globals above so `$state` is defined at module evaluation.
const { ledgerState } = await import('../src/lib/stores.svelte.js');

const PINNED_LEDGER = 'pl'.repeat(32);
const LEAF_LEDGER = 'aa'.repeat(32);

/** A fake wasm node whose pin state can be confirmed in place. */
function makePinNode() {
  const state = {
    ledgerPin: PINNED_LEDGER,
    ledgerTrust: 'unconfirmed',
    leafPins: [{ nodeId: 'leaf-a', ledger: LEAF_LEDGER, trust: 'unconfirmed' }],
    changes: [],
  };
  const node = {
    endpoint_id: () => 'self-node',
    ledger_status: () => ({
      address: '0.3.1',
      parent: 'parent',
      balance: null,
      height: null,
      pinned_ledger: state.ledgerPin,
      state_root: null,
      pending: 0,
      activity: 0,
      free() {},
    }),
    pin_status: () => ({
      status: state.changes.length
        ? 'changed'
        : state.ledgerTrust === 'confirmed'
          ? 'confirmed'
          : 'unconfirmed',
      ledger_pin: state.ledgerPin,
      ledger_trust: state.ledgerTrust,
      leaf_pins: state.leafPins.map((pin) => ({
        node_id: pin.nodeId,
        ledger: pin.ledger,
        trust: pin.trust,
        free() {},
      })),
      changes: state.changes.map((change) => ({
        node_id: change.nodeId,
        pinned: change.pinned,
        presented: change.presented,
        free() {},
      })),
      free() {},
    }),
    confirm_pin: (nodeId) => {
      if (nodeId === 'parent' && state.ledgerPin) {
        state.ledgerTrust = 'confirmed';
        state.changes = state.changes.filter((change) => change.nodeId !== nodeId);
        return;
      }
      const leaf = state.leafPins.find((pin) => pin.nodeId === nodeId);
      if (!leaf) throw new Error('no pin');
      leaf.trust = 'confirmed';
      state.changes = state.changes.filter((change) => change.nodeId !== nodeId);
    },
    export_ledger_state: () => new Uint8Array([9]),
  };
  return { node, state };
}

test('an unconfirmed TOFU pin does not establish trust', () => {
  const { node } = makePinNode();
  __setClientForTest(node);
  try {
    assert.equal(isTrustEstablished(), false);
    const trust = getTrustState();
    assert.equal(trust.established, false);
    assert.equal(trust.needsReestablish, true);
    assert.equal(trust.status, 'unconfirmed');
    assert.equal(trust.ledgerTrust, 'unconfirmed');
    assert.equal(trust.ledgerPinNode, 'parent');
    assert.equal(trust.pinnedLedger, PINNED_LEDGER);
    // The payee leaf pin is surfaced as unconfirmed too.
    assert.equal(trust.pinnedLeafKeys.length, 1);
  } finally {
    __setClientForTest(null);
  }
});

test('confirmPin flips an unconfirmed pin to confirmed and establishes trust', () => {
  const { node, state } = makePinNode();
  __setClientForTest(node);
  try {
    confirmPin('parent');
    assert.equal(state.ledgerTrust, 'confirmed');
    const trust = getTrustState();
    assert.equal(trust.established, true);
    assert.equal(trust.needsReestablish, false);
    assert.equal(trust.status, 'confirmed');
    assert.equal(trust.ledgerTrust, 'confirmed');
    assert.equal(isTrustEstablished(), true);
    // The confirmation was persisted.
    const stored = memory.getItem(`cawala.ledger.v1:self-node`);
    assert.ok(stored, 'the confirmed ledger state is persisted');
  } finally {
    __setClientForTest(null);
  }
});

test('a pin change is surfaced as changed and never adopted', () => {
  const { node, state } = makePinNode();
  state.changes = [{ nodeId: 'parent', pinned: PINNED_LEDGER, presented: 'zz'.repeat(32) }];
  __setClientForTest(node);
  try {
    const trust = getTrustState();
    assert.equal(trust.status, 'changed');
    assert.equal(trust.established, false);
    assert.equal(trust.changes.length, 1);
    assert.equal(trust.changes[0].nodeId, 'parent');
    assert.equal(trust.changes[0].pinned, PINNED_LEDGER);
    assert.equal(trust.changes[0].presented, 'zz'.repeat(32));
  } finally {
    __setClientForTest(null);
  }
});

test('confirming a leaf pin flips its trust and clears its change', () => {
  const { node, state } = makePinNode();
  state.changes = [{ nodeId: 'leaf-a', pinned: LEAF_LEDGER, presented: 'bb'.repeat(32) }];
  __setClientForTest(node);
  try {
    assert.equal(getTrustState().established, false);
    confirmPin('leaf-a');
    assert.equal(state.leafPins[0].trust, 'confirmed');
    assert.equal(state.changes.length, 0);
    const trust = getTrustState();
    assert.equal(trust.changes.length, 0);
    // The routing pin is still unconfirmed, so trust is not established.
    assert.equal(trust.established, false);
  } finally {
    __setClientForTest(null);
  }
});

test('a confirmed routing pin with a pending change does not establish trust via the module flag/store mirror', () => {
  const { node, state } = makePinNode();
  // The routing pin is already confirmed, but a payee leaf key changed.
  state.ledgerTrust = 'confirmed';
  state.changes = [{ nodeId: 'leaf-a', pinned: LEAF_LEDGER, presented: 'bb'.repeat(32) }];
  __setClientForTest(node);
  try {
    // `getTrustState()` already fails closed on a pending change...
    assert.equal(getTrustState().established, false);

    // ...and the module flag / store mirror must agree. Recompute the flag via
    // an explicit (idempotent) routing-pin confirmation, which must NOT clear
    // the unrelated leaf change.
    confirmPin('parent');
    assert.equal(state.changes.length, 1, 'the leaf change is preserved');
    assert.equal(
      ledgerState.trustEstablished,
      false,
      'a pending change must keep the module/store flag fail-closed',
    );
    assert.equal(isTrustEstablished(), false);

    // Clearing/confirming the remaining change flips it back on.
    confirmPin('leaf-a');
    assert.equal(state.changes.length, 0);
    assert.equal(
      ledgerState.trustEstablished,
      true,
      'no pending change means trust is established',
    );
    assert.equal(isTrustEstablished(), true);
  } finally {
    __setClientForTest(null);
  }
});

test('confirmPin rejects an unknown subject and changes nothing', () => {
  const { node } = makePinNode();
  __setClientForTest(node);
  try {
    assert.throws(() => confirmPin('absent'), /no pin/);
    assert.equal(getTrustState().established, false);
  } finally {
    __setClientForTest(null);
  }
});

test('mock mode never claims an established pin', () => {
  const trust = getTrustState();
  assert.equal(trust.mock, true);
  assert.equal(trust.established, false);
  assert.equal(trust.status, 'none');
  assert.deepEqual(trust.changes, []);
});
