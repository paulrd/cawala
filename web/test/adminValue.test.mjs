import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Admin value helpers (P4).
 *
 * `api.js` imports the Svelte rune stores and the `?raw` policy module, so the
 * rune primitive, storage and the raw loader are shimmed before it loads. The
 * wasm layer is not exercised: these are the pure predicates/helpers the value
 * path delegates to.
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
  canAdministerValue,
  valueErrorMessage,
  readPendingValueOp,
  clearPendingValueOp,
  adminIssue,
  adminBurn,
  __setClientForTest,
  VALUE_PENDING_KEY,
} = await import('../src/lib/api.js');
const { administeredNode, adminCapabilities, adminLock } = await import(
  '../src/lib/stores.svelte.js'
);

// ── canAdministerValue ───────────────────────────────────────────────────────

test('value actions need a non-self target and canAdminister', () => {
  assert.equal(canAdministerValue({ isSelf: false }, { canAdminister: true }), true);
  assert.equal(canAdministerValue({ isSelf: true }, { canAdminister: true }), false);
  assert.equal(canAdministerValue({ isSelf: false }, { canAdminister: false }), false);
  assert.equal(canAdministerValue({ isSelf: false }, {}), false);
  assert.equal(canAdministerValue({ isSelf: false }, null), false);
  assert.equal(canAdministerValue(null, { canAdminister: true }), false);
  assert.equal(canAdministerValue(undefined, { canAdminister: true }), false);
});

// ── In-flight persistence ────────────────────────────────────────────────────

const PENDING = {
  requestId: 'ab'.repeat(16),
  target: 'c1'.repeat(32),
  direction: 'issue',
  account: 'd2'.repeat(32),
  amount: 25,
  reason: 'top-up',
  at: 1_700_000_000_000,
};

function reset() {
  memory.clear();
}

test('a persisted pending op round-trips and clears', () => {
  reset();
  assert.equal(readPendingValueOp(), null);

  memory.setItem(VALUE_PENDING_KEY, JSON.stringify(PENDING));
  assert.deepEqual(readPendingValueOp(), PENDING);

  clearPendingValueOp();
  assert.equal(readPendingValueOp(), null);
});

test('clearPendingValueOp only clears a matching id', () => {
  reset();
  memory.setItem(VALUE_PENDING_KEY, JSON.stringify(PENDING));

  clearPendingValueOp('ff'.repeat(16));
  assert.deepEqual(readPendingValueOp(), PENDING, 'a different id must not clear');

  clearPendingValueOp(PENDING.requestId);
  assert.equal(readPendingValueOp(), null);
});

test('a malformed pending record reads as null', () => {
  reset();
  memory.setItem(VALUE_PENDING_KEY, '{ not json');
  assert.equal(readPendingValueOp(), null);

  memory.setItem(VALUE_PENDING_KEY, JSON.stringify({ requestId: 'short' }));
  assert.equal(readPendingValueOp(), null);

  memory.setItem(VALUE_PENDING_KEY, JSON.stringify({ ...PENDING, direction: 'nope' }));
  assert.equal(readPendingValueOp(), null);
});

// ── Reject-code copy mapping ─────────────────────────────────────────────────

test('value reject codes map to honest copy', () => {
  const limit = valueErrorMessage('admin request rejected: limit_exceeded');
  assert.match(limit, /limit/i);
  // Actionable: point at the operator and a smaller amount (no fabricated numbers).
  assert.match(limit, /operator/i);
  assert.match(limit, /smaller amount/i);

  const balance = valueErrorMessage('admin request rejected: insufficient_balance');
  assert.match(balance, /exceeds the account/i);

  const unauthorized = valueErrorMessage('admin request rejected: unauthorized');
  assert.match(unauthorized, /designated administrator/i);

  // An unknown code degrades to a generic value message, never the raw marker.
  const unknown = valueErrorMessage('admin request rejected: bogus');
  assert.doesNotMatch(unknown, /admin request rejected/);

  // A non-marker error message is passed through unchanged.
  assert.equal(valueErrorMessage('network down'), 'network down');
});

// ── Live wasm boundary: the amount must cross as a bigint ────────────────────

const FAKE_DTO = {
  request_id: 'ab'.repeat(16),
  account: 'acct',
  direction: 'issue',
  amount: 25,
  balance_after: 25,
  seq: 1,
  entry_hash: '00'.repeat(32),
  duplicate: false,
  free() {},
};

/** Install a fake live client and open the admin-target gates for a test. */
function enterLiveMode(calls) {
  administeredNode.isSelf = false;
  adminCapabilities.canAdminister = true;
  adminLock.unlocked = true;
  __setClientForTest({
    async admin_issue(...args) {
      calls.push(['issue', ...args]);
      return FAKE_DTO;
    },
    async admin_burn(...args) {
      calls.push(['burn', ...args]);
      return FAKE_DTO;
    },
  });
}

function restoreMockMode() {
  __setClientForTest(null);
  administeredNode.isSelf = true;
  adminCapabilities.canAdminister = false;
  adminLock.unlocked = false;
}

test('live issue/burn pass the amount as a bigint to wasm', async () => {
  reset();
  const calls = [];
  enterLiveMode(calls);
  try {
    await adminIssue('acct', 25, 'top-up', 'target');
    assert.equal(calls.length, 1);
    const [kind, target, requestId, account, amount, reason] = calls[0];
    assert.equal(kind, 'issue');
    assert.equal(target, 'target');
    assert.equal(typeof requestId, 'string');
    assert.equal(account, 'acct');
    assert.equal(typeof amount, 'bigint', 'the i64 param needs a BigInt');
    assert.equal(amount, 25n);
    assert.equal(reason, 'top-up');

    await adminBurn('acct', 7, 'write-off', 'target');
    assert.equal(calls.length, 2);
    assert.equal(typeof calls[1][4], 'bigint');
    assert.equal(calls[1][4], 7n);
  } finally {
    restoreMockMode();
  }
});

test('live value ops reject a non-integer or non-positive amount before wasm', async () => {
  reset();
  const calls = [];
  enterLiveMode(calls);
  try {
    for (const bad of [2.5, 0, -3, Number.NaN, Number.POSITIVE_INFINITY]) {
      await assert.rejects(
        () => adminIssue('acct', bad, 'reason', 'target'),
        /positive whole number/i,
      );
      await assert.rejects(
        () => adminBurn('acct', bad, 'reason', 'target'),
        /positive whole number/i,
      );
    }
    assert.equal(calls.length, 0, 'no wasm call is made for an invalid amount');
  } finally {
    restoreMockMode();
  }
});
