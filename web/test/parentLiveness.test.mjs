import { test } from 'node:test';
import assert from 'node:assert/strict';

// ── localStorage shim (installed before the module is imported) ──────────────

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

const {
  PARENT_TRACKER_KEY,
  PARENT_TRACKER_VERSION,
  PARENT_STATUS_KEYS,
  emptyTracker,
  normalizeTracker,
  applyProbe,
  trackerStatus,
  loadTracker,
  recordParentProbe,
  getParentStatus,
} = await import('../src/lib/parentLiveness.js');

// ── Fixtures ─────────────────────────────────────────────────────────────────

const PARENT = 'a1'.repeat(32);
const PARENT_B = 'b2'.repeat(32);

const EMPTY_STATUS = {
  parent: null,
  reachable: true,
  lastOkAt: null,
  unreachableSince: null,
  consecutiveFailures: 0,
};

function reset() {
  memory.clear();
}

function raw() {
  const value = memory.getItem(PARENT_TRACKER_KEY);
  return value == null ? null : JSON.parse(value);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('a failed probe sets unreachableSince and increments failures', () => {
  reset();
  const next = recordParentProbe(PARENT, false, 1000);

  assert.deepEqual(getParentStatus(PARENT), {
    parent: PARENT,
    reachable: false,
    lastOkAt: null,
    unreachableSince: 1000,
    consecutiveFailures: 1,
  });
  assert.equal(next.consecutiveFailures, 1);
  assert.equal(next.firstFailureAt, 1000);
});

test('repeated failures keep the first-failure timestamp and count up', () => {
  reset();
  recordParentProbe(PARENT, true, 500);
  recordParentProbe(PARENT, false, 1000);
  recordParentProbe(PARENT, false, 2000);

  const status = getParentStatus(PARENT);
  assert.equal(status.reachable, false);
  assert.equal(status.consecutiveFailures, 2);
  assert.equal(status.unreachableSince, 1000);
  // A later failure must not erase the last success.
  assert.equal(status.lastOkAt, 500);
});

test('a successful probe clears failures and stamps lastOkAt', () => {
  reset();
  recordParentProbe(PARENT, false, 1000);
  recordParentProbe(PARENT, false, 1500);
  recordParentProbe(PARENT, true, 2000);

  assert.deepEqual(getParentStatus(PARENT), {
    parent: PARENT,
    reachable: true,
    lastOkAt: 2000,
    unreachableSince: null,
    consecutiveFailures: 0,
  });
  const stored = raw();
  assert.equal(stored.firstFailureAt, null);
  assert.equal(stored.consecutiveFailures, 0);
});

test('a changed parent resets and ignores the stale record', () => {
  reset();
  recordParentProbe(PARENT, false, 1000);
  recordParentProbe(PARENT, false, 2000);

  // The live parent is now B: the stale A record must not colour it.
  assert.deepEqual(getParentStatus(PARENT_B), {
    ...EMPTY_STATUS,
    parent: PARENT_B,
  });

  // A probe against B starts a fresh record.
  const next = recordParentProbe(PARENT_B, false, 3000);
  assert.equal(next.parent, PARENT_B);
  assert.equal(next.consecutiveFailures, 1);
  assert.equal(next.firstFailureAt, 3000);
  assert.equal(next.lastOkAt, null);
  assert.equal(raw().parent, PARENT_B);
});

test('parentStatus()/getParentStatus shape is exactly the frozen keys', () => {
  reset();
  recordParentProbe(PARENT, false, 1000);

  const failing = getParentStatus(PARENT);
  assert.deepEqual(Object.keys(failing), [...PARENT_STATUS_KEYS]);
  assert.deepEqual(failing, {
    parent: PARENT,
    reachable: false,
    lastOkAt: null,
    unreachableSince: 1000,
    consecutiveFailures: 1,
  });

  // The neutral (no record) status has the same exact shape.
  const neutral = getParentStatus(null);
  assert.deepEqual(Object.keys(neutral), [...PARENT_STATUS_KEYS]);
  assert.deepEqual(neutral, EMPTY_STATUS);

  // A record that has not yet failed is reachable by definition.
  reset();
  recordParentProbe(PARENT, true, 1000);
  const reachable = getParentStatus(PARENT);
  assert.deepEqual(Object.keys(reachable), [...PARENT_STATUS_KEYS]);
  assert.equal(reachable.reachable, true);
});

test('storage-unavailable path never throws and reads as reachable', () => {
  const original = globalThis.localStorage;
  delete globalThis.localStorage;
  try {
    assert.doesNotThrow(() => recordParentProbe(PARENT, false, 1000));
    assert.equal(loadTracker(), null);
    assert.deepEqual(getParentStatus(PARENT), {
      ...EMPTY_STATUS,
      parent: PARENT,
    });
  } finally {
    globalThis.localStorage = original;
  }
});

test('throwing storage never throws and reads as reachable', () => {
  const original = globalThis.localStorage;
  globalThis.localStorage = {
    getItem() {
      throw new Error('boom');
    },
    setItem() {
      throw new Error('boom');
    },
    removeItem() {
      throw new Error('boom');
    },
  };
  try {
    assert.doesNotThrow(() => recordParentProbe(PARENT, false, 1000));
    assert.deepEqual(getParentStatus(PARENT), {
      ...EMPTY_STATUS,
      parent: PARENT,
    });
  } finally {
    globalThis.localStorage = original;
  }
});

test('malformed or unknown-version records are ignored', () => {
  reset();

  memory.setItem(PARENT_TRACKER_KEY, '{not json');
  assert.deepEqual(getParentStatus(PARENT), {
    ...EMPTY_STATUS,
    parent: PARENT,
  });

  memory.setItem(PARENT_TRACKER_KEY, JSON.stringify({ v: 2, parent: PARENT }));
  assert.equal(getParentStatus(PARENT).consecutiveFailures, 0);

  memory.setItem(
    PARENT_TRACKER_KEY,
    JSON.stringify({
      v: PARENT_TRACKER_VERSION,
      parent: PARENT,
      firstFailureAt: null,
      lastOkAt: null,
      consecutiveFailures: 3,
    }),
  );
  // Failing without a first-failure timestamp is inconsistent: ignore it.
  assert.equal(getParentStatus(PARENT).consecutiveFailures, 0);
  assert.equal(getParentStatus(PARENT).reachable, true);
});

test('pure reducer does not mutate its input', () => {
  const previous = emptyTracker(PARENT);
  const nextFailure = applyProbe(previous, PARENT, false, 1000);
  assert.equal(previous.consecutiveFailures, 0);
  assert.equal(previous.firstFailureAt, null);
  assert.equal(nextFailure.consecutiveFailures, 1);

  const nextOk = applyProbe(nextFailure, PARENT, true, 2000);
  assert.equal(nextFailure.consecutiveFailures, 1);
  assert.equal(nextOk.consecutiveFailures, 0);
  assert.equal(nextOk.lastOkAt, 2000);
});

test('recordParentProbe with no parent is a no-op', () => {
  reset();
  assert.equal(recordParentProbe(null, false, 1000), null);
  assert.equal(recordParentProbe('', false, 1000), null);
  assert.equal(memory.getItem(PARENT_TRACKER_KEY), null);
});

test('normalizeTracker rejects non-records and missing parents', () => {
  assert.equal(normalizeTracker(null), null);
  assert.equal(normalizeTracker([]), null);
  assert.equal(normalizeTracker({ v: 1, parent: '' }), null);
  assert.deepEqual(normalizeTracker({ v: 1, parent: PARENT }), {
    v: 1,
    parent: PARENT,
    firstFailureAt: null,
    lastOkAt: null,
    consecutiveFailures: 0,
  });
});

test('trackerStatus is pure and ignores a mismatched parent', () => {
  const stored = applyProbe(null, PARENT, true, 1234);
  const matched = trackerStatus(stored, PARENT);
  assert.equal(matched.parent, PARENT);
  assert.equal(matched.lastOkAt, 1234);
  const mismatched = trackerStatus(stored, PARENT_B);
  assert.equal(mismatched.parent, PARENT_B);
  assert.equal(mismatched.consecutiveFailures, 0);
});
