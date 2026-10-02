import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Topology-action gating (P4).
 *
 * `api.js` imports the Svelte rune stores, so `$state` and localStorage are
 * shimmed before the module loads. These are the pure predicates the NodePage
 * and the api action functions delegate to.
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

const { canAdministerTopology, canMoveChild } = await import('../src/lib/api.js');

test('topology actions need a non-self target and a topology scope', () => {
  const granted = { scopes: { joins: true, topology: true, value: false } };
  const noTopology = { scopes: { joins: true, topology: false, value: true } };

  assert.equal(canAdministerTopology({ isSelf: false }, granted), true);
  // This browser's own node is never a delegated-admin target.
  assert.equal(canAdministerTopology({ isSelf: true }, granted), false);
  // A joins-only or value-only grant cannot re-slot/detach.
  assert.equal(canAdministerTopology({ isSelf: false }, noTopology), false);
  assert.equal(canAdministerTopology({ isSelf: false }, { scopes: {} }), false);
  assert.equal(canAdministerTopology({ isSelf: false }, null), false);
  assert.equal(canAdministerTopology(null, granted), false);
});

test('only node children can be re-slotted', () => {
  assert.equal(canMoveChild('node'), true);
  assert.equal(canMoveChild('user'), false);
  assert.equal(canMoveChild(null), false);
  assert.equal(canMoveChild(undefined), false);
});
