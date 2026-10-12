import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * R1 read-getter consumption (P1-B).
 *
 * `api.js` imports the Svelte rune stores and the `?raw` policy module, so the
 * rune primitive, storage and the raw loader are shimmed before it loads. The
 * wasm client is replaced by a fake via `__setClientForTest`; these tests cover
 * the pure DTO->plain mapping and free discipline of the new getters.
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

const {
  __setClientForTest,
  getPendingOrders,
  getPinnedLeafKeys,
  getPendingJoinOutbound,
  getClientStateInfo,
  getJoinStatus,
  getLedgerStatus,
  getActivityLog,
  getTrustState,
  isTrustEstablished,
} = await import('../src/lib/api.js');
const { ledgerState } = await import('../src/lib/stores.svelte.js');
const { ACTIVITY_TYPES } = await import('../src/lib/constants.js');

// ── Fake wasm DTOs ───────────────────────────────────────────────────────────

function makeOrder() {
  const freed = [];
  const dto = {
    from: 'payer',
    to: 'payee',
    amount: 10,
    nonce: 1,
    expiry: 2,
    operator: 'op'.repeat(2),
    auth_nonce: 3,
    order_hash: 'aa'.repeat(32),
    signature: 'bb'.repeat(64),
    sent_at: 4,
    payee_addr: '0.3.2',
    payer_leaf: true,
    pinned_leaf: {
      node_id: 'leaf-node',
      ledger: 'cc'.repeat(32),
      free() {
        freed.push('pin');
      },
    },
    free() {
      freed.push('order');
    },
    _freed: freed,
  };
  return dto;
}

function makePin() {
  const freed = [];
  return {
    node_id: 'leaf-node',
    ledger: 'cc'.repeat(32),
    free() {
      freed.push('pin');
    },
    _freed: freed,
  };
}

function makeLiveNode(overrides = {}) {
  const order = makeOrder();
  const pin = makePin();
  const freed = [];
  const node = {
    endpoint_id: () => 'self-node',
    pending_orders: () => [order],
    pinned_leaf_keys: () => [pin],
    pending_join_outbound: () => ({
      node: 'me',
      kind: 'user',
      operator: 'op'.repeat(2),
      ledger: undefined,
      desired_slot: 2,
      location_hint: undefined,
      nonce: 9,
      expiry: 1000,
      parent: 'parent',
      pinned_operator: 'po'.repeat(2),
      sent_at: 500,
      free() {
        freed.push('join');
      },
    }),
    client_state_info: () => ({
      state_version: 1,
      ledger_version: 3,
      free() {
        freed.push('info');
      },
    }),
    join_status: () => ({
      state: 'rejected',
      parent: 'parent',
      slot: undefined,
      address: undefined,
      reason: 'nope',
      reject_code: 'slot_taken',
      free() {
        freed.push('join-status');
      },
    }),
    ledger_status: () => ({
      address: '0.3.1',
      parent: 'parent',
      balance: 5,
      height: 7,
      pinned_ledger: 'pl'.repeat(32),
      state_root: 'sr'.repeat(32),
      pending: 7,
      activity: 2,
      free() {
        freed.push('ledger-status');
      },
    }),
    ...overrides,
  };
  return { node, freed, order, pin };
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('getPendingOrders maps the full order and frees nested + outer handles', () => {
  const { node, order } = makeLiveNode();
  __setClientForTest(node);
  try {
    const rows = getPendingOrders();
    assert.equal(rows.length, 1);
    assert.deepEqual(rows[0], {
      from: 'payer',
      to: 'payee',
      amount: 10,
      nonce: 1,
      expiry: 2,
      operator: 'op'.repeat(2),
      authNonce: 3,
      orderHash: 'aa'.repeat(32),
      signature: 'bb'.repeat(64),
      sentAt: 4,
      payeeAddr: '0.3.2',
      payerLeaf: true,
      pinnedLeaf: { nodeId: 'leaf-node', ledger: 'cc'.repeat(32) },
    });
    assert.deepEqual(order._freed, ['pin', 'order']);
  } finally {
    __setClientForTest(null);
  }
});

test('getPendingOrders tolerates a build without the getter', () => {
  __setClientForTest({ endpoint_id: () => 'x' });
  try {
    assert.deepEqual(getPendingOrders(), []);
  } finally {
    __setClientForTest(null);
  }
});

test('getPinnedLeafKeys maps and frees the TOFU anchors', () => {
  const { node, pin } = makeLiveNode();
  __setClientForTest(node);
  try {
    assert.deepEqual(getPinnedLeafKeys(), [{ nodeId: 'leaf-node', ledger: 'cc'.repeat(32) }]);
    assert.deepEqual(pin._freed, ['pin']);
  } finally {
    __setClientForTest(null);
  }
});

test('getPendingJoinOutbound maps the outbound join request', () => {
  const { node, freed } = makeLiveNode();
  __setClientForTest(node);
  try {
    assert.deepEqual(getPendingJoinOutbound(), {
      node: 'me',
      kind: 'user',
      operator: 'op'.repeat(2),
      ledger: null,
      desiredSlot: 2,
      locationHint: null,
      nonce: 9,
      expiry: 1000,
      parent: 'parent',
      pinnedOperator: 'po'.repeat(2),
      sentAt: 500,
    });
    assert.ok(freed.includes('join'));
  } finally {
    __setClientForTest(null);
  }
});

test('getClientStateInfo maps the on-disk blob versions', () => {
  const { node, freed } = makeLiveNode();
  __setClientForTest(node);
  try {
    assert.deepEqual(getClientStateInfo(), { stateVersion: 1, ledgerVersion: 3 });
    assert.ok(freed.includes('info'));
  } finally {
    __setClientForTest(null);
  }
});

test('getJoinStatus surfaces rejectCode and the pending outbound join', () => {
  const { node } = makeLiveNode();
  __setClientForTest(node);
  try {
    const status = getJoinStatus();
    assert.equal(status.state, 'rejected');
    assert.equal(status.rejectCode, 'slot_taken');
    assert.equal(status.reason, 'nope');
    assert.equal(status.pendingJoin.parent, 'parent');
    assert.equal(status.pendingJoin.desiredSlot, 2);
  } finally {
    __setClientForTest(null);
  }
});

test('getLedgerStatus surfaces stateRoot', () => {
  const { node } = makeLiveNode();
  __setClientForTest(node);
  try {
    const status = getLedgerStatus();
    assert.equal(status.stateRoot, 'sr'.repeat(32));
    assert.equal(status.pinnedLedger, 'pl'.repeat(32));
  } finally {
    __setClientForTest(null);
  }
});

test('settlement activity carries the failing hop (failedAt)', async () => {
  // A bare live client keeps `getActivityLog` off its mock path; the entries
  // themselves come from the reactive store.
  __setClientForTest({ endpoint_id: () => 'self-node' });
  ledgerState.activity = [
    {
      id: 's:hash',
      type: ACTIVITY_TYPES.SETTLEMENT,
      from: null,
      to: 'payee',
      amount: 10,
      timestamp: new Date(0).toISOString(),
      status: 'partial',
      reason: 'hop failed',
      failedAt: 'leaf-b',
      orderHash: 'hash',
    },
  ];
  try {
    const rows = await getActivityLog();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].failedAt, 'leaf-b');
    assert.equal(rows[0].status, 'partial');
  } finally {
    ledgerState.activity = [];
    __setClientForTest(null);
  }
});

test('trust state is fail-closed until anchors are restored', () => {
  const { node } = makeLiveNode();
  __setClientForTest(node);
  try {
    assert.equal(isTrustEstablished(), false);
    const trust = getTrustState();
    assert.equal(trust.established, false);
    assert.equal(trust.needsReestablish, true);
    assert.equal(trust.pinnedLedger, 'pl'.repeat(32));
    assert.equal(trust.pinnedLeafKeys.length, 1);
  } finally {
    __setClientForTest(null);
  }
  // Mock mode never claims established trust.
  const mockTrust = getTrustState();
  assert.equal(mockTrust.mock, true);
  assert.equal(mockTrust.needsReestablish, false);
});
