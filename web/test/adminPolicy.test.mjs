import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Admin unlock policy acknowledgement (R6, P4).
 *
 * `adminPolicy.js` remembers only the *hash* of the policy document that was
 * acknowledged, so editing `ADMIN_POLICY.md` invalidates every past
 * acknowledgement. The unlocked flag itself lives in memory (stores.svelte.js),
 * never here.
 *
 * The module resolves storage through `window.localStorage`, so the tests shim
 * a `window` plus a `localStorage` before importing it.
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

const {
  POLICY_STORAGE_KEY,
  POLICY_TEXT,
  POLICY_HASH,
  hashPolicyText,
  readAcknowledgedPolicy,
  writeAcknowledgedPolicy,
  policyAcknowledgementCurrent,
} = await import('../src/lib/adminPolicy.js');

function reset() {
  memory.clear();
}

// ── hashPolicyText ───────────────────────────────────────────────────────────

test('hashPolicyText is a deterministic 8-hex FNV-1a', () => {
  assert.equal(hashPolicyText(''), '811c9dc5', 'empty string anchors the algorithm');
  assert.match(hashPolicyText('a'), /^[0-9a-f]{8}$/);
  assert.equal(hashPolicyText('hello'), hashPolicyText('hello'), 'deterministic');
  assert.notEqual(hashPolicyText('hello'), hashPolicyText('hello!'));
  assert.equal(hashPolicyText(null), hashPolicyText(''), 'null reads as empty');
});

test('POLICY_HASH is the hash of the shipped document', () => {
  assert.equal(POLICY_HASH, hashPolicyText(POLICY_TEXT));
  assert.match(POLICY_HASH, /^[0-9a-f]{8}$/);
});

// ── acknowledged policy storage ──────────────────────────────────────────────

test('nothing is acknowledged before the gate is used', () => {
  reset();
  assert.equal(readAcknowledgedPolicy(), null);
  assert.equal(policyAcknowledgementCurrent(), false);
});

test('a written acknowledgement round-trips with its timestamp', () => {
  reset();
  assert.equal(writeAcknowledgedPolicy('deadbeef'), true);
  const stored = readAcknowledgedPolicy();
  assert.equal(stored.hash, 'deadbeef');
  assert.equal(typeof stored.at, 'number');
  assert.equal(policyAcknowledgementCurrent(), false, 'not the shipped hash');
});

test('default acknowledgement records the shipped hash and is current', () => {
  reset();
  writeAcknowledgedPolicy();
  assert.deepEqual(readAcknowledgedPolicy().hash, POLICY_HASH);
  assert.equal(policyAcknowledgementCurrent(), true);
});

test('a changed policy hash invalidates a stale acknowledgement', () => {
  reset();
  // The user acknowledged an older revision of the document.
  const oldHash = hashPolicyText(`${POLICY_TEXT}\n\nold revision`);
  assert.notEqual(oldHash, POLICY_HASH);
  writeAcknowledgedPolicy(oldHash);
  assert.equal(readAcknowledgedPolicy().hash, oldHash);
  assert.equal(
    policyAcknowledgementCurrent(),
    false,
    'an edited document must invalidate the stored acknowledgement',
  );

  // Re-acknowledging the current document makes it current again.
  writeAcknowledgedPolicy(POLICY_HASH);
  assert.equal(policyAcknowledgementCurrent(), true);
});

test('a corrupt stored entry reads as never acknowledged', () => {
  reset();
  memory.setItem(POLICY_STORAGE_KEY, '{ not json');
  assert.equal(readAcknowledgedPolicy(), null);
  memory.setItem(POLICY_STORAGE_KEY, JSON.stringify({ hash: '' }));
  assert.equal(readAcknowledgedPolicy(), null);
  memory.setItem(POLICY_STORAGE_KEY, JSON.stringify({ nope: true }));
  assert.equal(readAcknowledgedPolicy(), null);
});

test('writeAcknowledgedPolicy is best-effort when storage is unavailable', () => {
  reset();
  const savedWindow = globalThis.window;
  globalThis.window = {};
  try {
    assert.equal(writeAcknowledgedPolicy(), false);
    assert.equal(readAcknowledgedPolicy(), null);
    assert.equal(policyAcknowledgementCurrent(), false);
  } finally {
    globalThis.window = savedWindow;
  }
});
