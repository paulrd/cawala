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
  VALUE_PENDING_KEY,
} = await import('../src/lib/api.js');

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
