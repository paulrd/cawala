import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Topology/designation gating (P4).
 *
 * `api.js` imports the Svelte rune stores and the `?raw` policy module, so the
 * rune primitive, storage and the raw loader are shimmed before it loads. These
 * are the pure predicates the Admin page delegates to: topology actions need an
 * unlocked admin mode pointed at a non-self ancestor, and only `node` children
 * can be re-slotted.
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
globalThis.window = { localStorage: globalThis.localStorage };
globalThis.$state = (value) => value;

const { canAdministerTopology, canMoveChild } = await import('../src/lib/api.js');

test('topology actions need a non-self target and canAdminister', () => {
  assert.equal(canAdministerTopology({ isSelf: false }, { canAdminister: true }), true);
  // This browser's own node is never an administered target.
  assert.equal(canAdministerTopology({ isSelf: true }, { canAdminister: true }), false);
  // Locked admin mode (canAdminister false) cannot re-slot/detach.
  assert.equal(canAdministerTopology({ isSelf: false }, { canAdminister: false }), false);
  assert.equal(canAdministerTopology({ isSelf: false }, {}), false);
  assert.equal(canAdministerTopology({ isSelf: false }, null), false);
  assert.equal(canAdministerTopology(null, { canAdminister: true }), false);
  assert.equal(canAdministerTopology(undefined, { canAdminister: true }), false);
});

test('only node children can be re-slotted', () => {
  assert.equal(canMoveChild('node'), true);
  assert.equal(canMoveChild('user'), false);
  assert.equal(canMoveChild(null), false);
  assert.equal(canMoveChild(undefined), false);
});
