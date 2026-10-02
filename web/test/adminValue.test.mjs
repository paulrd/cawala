import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Delegated value administration helpers (P5).
 *
 * `api.js` imports the Svelte rune stores, so `$state` and localStorage are
 * shimmed before the module loads. The wasm layer is not exercised: these are
 * the pure predicates/helpers the value path delegates to.
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
globalThis.$state = (value) => value;

const {
  canAdministerValue,
  valueErrorMessage,
  readPendingValueOp,
  clearPendingValueOp,
  VALUE_PENDING_KEY,
  AdminLockedError,
  AdminSeedProtectionRequiredError,
  ensureValueSeedUnlocked,
  protectValueSeed,
} = await import('../src/lib/api.js');
const { valueReasonErrorVisible } = await import('../src/lib/adminView.js');
const {
  addAdminEntry,
  findAdminNode,
  protectAdminSeed,
  lockAdminSeed,
  adminSeedState,
} = await import('../src/lib/adminKeys.js');

// ── canAdministerValue ───────────────────────────────────────────────────────

test('value actions need a non-self target and a value scope', () => {
  const granted = { scopes: { joins: false, topology: false, value: true } };
  const noValue = { scopes: { joins: true, topology: true, value: false } };

  assert.equal(canAdministerValue({ isSelf: false }, granted), true);
  assert.equal(canAdministerValue({ isSelf: true }, granted), false);
  assert.equal(canAdministerValue({ isSelf: false }, noValue), false);
  assert.equal(canAdministerValue({ isSelf: false }, { scopes: {} }), false);
  assert.equal(canAdministerValue({ isSelf: false }, null), false);
  assert.equal(canAdministerValue(null, granted), false);
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
  assert.match(unauthorized, /expired or revoked/i);

  // An unknown code degrades to a generic value message, never the raw marker.
  const unknown = valueErrorMessage('admin request rejected: bogus');
  assert.doesNotMatch(unknown, /admin request rejected/);

  // A non-marker error message is passed through unchanged.
  assert.equal(valueErrorMessage('network down'), 'network down');
});

// ── Protected value seeds (P6) ───────────────────────────────────────────────

const NODE_A = 'a1'.repeat(32);
const NODE_JOINS = 'b2'.repeat(32);
const PUB_A = 'e5'.repeat(32);
const SEED_A = 'c3'.repeat(32);

test('AdminLockedError and AdminSeedProtectionRequiredError are typed', () => {
  const locked = new AdminLockedError(NODE_A);
  assert.equal(locked.name, 'AdminLockedError');
  assert.equal(locked.code, 'ADMIN_LOCKED');
  assert.equal(locked.nodeId, NODE_A);
  assert.match(locked.message, /locked/i);

  const required = new AdminSeedProtectionRequiredError(NODE_A);
  assert.equal(required.name, 'AdminSeedProtectionRequiredError');
  assert.equal(required.code, 'ADMIN_SEED_PROTECT_REQUIRED');
  assert.equal(required.nodeId, NODE_A);
  assert.match(required.message, /protected with a passphrase/i);
});

test('ensureValueSeedUnlocked requires protection for value keys and passes others', async () => {
  reset();
  const now = 1_700_000_000_000;

  // Absent -> unavailable.
  assert.throws(
    () => ensureValueSeedUnlocked(NODE_A),
    (err) => err.name === 'AdminUnavailableError',
  );

  // A plain value key must be wrapped first ("required", not opt-in).
  addAdminEntry({ nodeId: NODE_A, adminSeedHex: SEED_A, adminPubHex: PUB_A, grantedAt: now, expiresAt: now + 1000, scopes: ['value'] });
  assert.throws(
    () => ensureValueSeedUnlocked(NODE_A),
    (err) =>
      err instanceof AdminSeedProtectionRequiredError &&
      err.code === 'ADMIN_SEED_PROTECT_REQUIRED' &&
      err.nodeId === NODE_A,
  );

  // A plain joins key is unaffected (value actions never target it).
  addAdminEntry({ nodeId: NODE_JOINS, adminSeedHex: SEED_A, adminPubHex: PUB_A, grantedAt: now, expiresAt: now + 1000 });
  assert.equal(ensureValueSeedUnlocked(NODE_JOINS), undefined);

  // After protection the key is unlocked for the session -> passes.
  await protectAdminSeed(NODE_A, 'passphrase');
  assert.equal(ensureValueSeedUnlocked(NODE_A), undefined);

  // Locked -> AdminLockedError.
  lockAdminSeed(NODE_A);
  assert.throws(
    () => ensureValueSeedUnlocked(NODE_A),
    (err) => err instanceof AdminLockedError && err.code === 'ADMIN_LOCKED' && err.nodeId === NODE_A,
  );
});

test('protectValueSeed wraps value keys and refuses non-value entries', async () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry({ nodeId: NODE_A, adminSeedHex: SEED_A, adminPubHex: PUB_A, grantedAt: now, expiresAt: now + 1000, scopes: ['value'] });
  addAdminEntry({ nodeId: NODE_JOINS, adminSeedHex: SEED_A, adminPubHex: PUB_A, grantedAt: now, expiresAt: now + 1000 });

  await assert.rejects(() => protectValueSeed(NODE_JOINS, 'passphrase'), /value scope required/);
  assert.equal(findAdminNode(NODE_JOINS).seedProtected, false);

  await protectValueSeed(NODE_A, 'passphrase');
  assert.equal(findAdminNode(NODE_A).seedProtected, true);
  assert.equal(findAdminNode(NODE_A).seedKind, 'pbkdf2-aes-gcm');
  assert.equal(adminSeedState(NODE_A), 'unlocked');
  assert.equal(ensureValueSeedUnlocked(NODE_A), undefined);
});

test('valueReasonErrorVisible only shows after touch and while invalid', () => {
  assert.equal(valueReasonErrorVisible(false, false), false);
  assert.equal(valueReasonErrorVisible(false, true), false);
  assert.equal(valueReasonErrorVisible(true, true), false);
  assert.equal(valueReasonErrorVisible(true, false), true);
  assert.equal(valueReasonErrorVisible(undefined, false), false);
});
