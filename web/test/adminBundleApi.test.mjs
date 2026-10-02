import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * API-layer admin-grant bundle import.
 *
 * `api.js` imports the Svelte rune stores, so the rune primitives are shimmed
 * before the module is loaded. The wasm parser itself is not available under
 * `node --test`, so `applyAdminBundle`'s mock-mode typed error and the
 * post-verification `applyAdminGrantInfo` path (which is what runs after a
 * bundle has been parsed and its signature verified) are exercised here.
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
// Svelte 5 runes are compiled away by the bundler; a passthrough is enough for
// importing the store module under plain Node.
globalThis.$state = (value) => value;

const { applyAdminBundle, applyAdminGrantInfo, getAdministeredNode } = await import('../src/lib/api.js');
const { addAdminEntry, findAdminNode, GRANT_SOURCE } = await import('../src/lib/adminKeys.js');

const NODE_A = 'a1'.repeat(32);
const SEED_A = 'c3'.repeat(32);
const PUB_A = 'e5'.repeat(32);

function reset() {
  memory.clear();
}

function seedEntry({ grantedAt = 1_700_000_000_000, expiresAt = 1_700_000_060_000 } = {}) {
  addAdminEntry({ nodeId: NODE_A, adminSeedHex: SEED_A, adminPubHex: PUB_A, grantedAt, expiresAt });
}

test('applyAdminBundle rejects an empty uri', async () => {
  reset();
  await assert.rejects(() => applyAdminBundle('   '), /Paste an admin bundle link/);
});

test('applyAdminBundle is a typed error in mock mode', async () => {
  reset();
  // `_useMock` defaults to true; the web client cannot parse/verify bundles.
  await assert.rejects(
    () => applyAdminBundle('cawala://admin?node=x&grant=y'),
    (err) => {
      assert.equal(err.name, 'AdminUnavailableError');
      assert.equal(err.code, 'ADMIN_UNAVAILABLE');
      return true;
    },
  );
});

test('applyAdminGrantInfo requires a stored key for the bundle node', () => {
  reset();
  assert.throws(
    () =>
      applyAdminGrantInfo({
        node: NODE_A,
        admin: PUB_A,
        scopes: ['joins'],
        grantedAt: 1_000,
        expiry: 2_000,
      }),
    /generate a key for this node first/,
  );
});

test('applyAdminGrantInfo rejects a bundle for a different admin key', () => {
  reset();
  const now = 1_700_000_000_000;
  seedEntry({ grantedAt: now, expiresAt: now + 1000 });
  assert.throws(
    () =>
      applyAdminGrantInfo({
        node: NODE_A,
        admin: 'ff'.repeat(32),
        scopes: ['joins'],
        grantedAt: now,
        expiry: now + 2000,
      }),
    /different admin key/,
  );
  // Nothing changed.
  assert.equal(findAdminNode(NODE_A).grantSource, GRANT_SOURCE.MANUAL);
});

test('applyAdminGrantInfo applies verified scopes/TTL and syncs the view', () => {
  reset();
  const now = 1_700_000_000_000;
  seedEntry({ grantedAt: now, expiresAt: now + 1000 });

  const applied = applyAdminGrantInfo({
    node: NODE_A.toUpperCase(),
    admin: PUB_A.toUpperCase(),
    scopes: ['topology'],
    grantedAt: now,
    expiry: now + 30 * 24 * 3600 * 1000,
    label: 'operator-granted',
  });

  assert.deepEqual(applied.scopes, ['topology']);
  assert.equal(applied.grantSource, GRANT_SOURCE.BUNDLE);
  assert.equal(applied.label, 'operator-granted');
  assert.equal(findAdminNode(NODE_A).grantSource, GRANT_SOURCE.BUNDLE);

  // `grantSource` flows into the administered-node view.
  const view = getAdministeredNode();
  assert.equal(view.nodeId, NODE_A);
  assert.equal(view.grantSource, GRANT_SOURCE.BUNDLE);
  assert.deepEqual(view.scopes, ['topology']);
});

test('applyAdminGrantInfo refuses empty/unknown scopes via applyAdminGrant', () => {
  reset();
  const now = 1_700_000_000_000;
  seedEntry({ grantedAt: now, expiresAt: now + 1000 });
  for (const scopes of [[], ['bogus']]) {
    assert.throws(
      () =>
        applyAdminGrantInfo({
          node: NODE_A,
          admin: PUB_A,
          scopes,
          grantedAt: now,
          expiry: now + 2000,
        }),
      /scope|at least one/,
    );
  }
  assert.equal(findAdminNode(NODE_A).grantSource, GRANT_SOURCE.MANUAL);
});
