import { test } from 'node:test';
import assert from 'node:assert/strict';

// ── localStorage shim (must be installed before the module is imported) ──────

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
  loadAdminEntries,
  listAdminNodes,
  findAdminNode,
  activeAdminNode,
  adminSeedBytes,
  addAdminEntry,
  removeAdminNode,
  clearAllAdminEntries,
} = await import('../src/lib/adminKeys.js');

// ── Fixtures ─────────────────────────────────────────────────────────────────

const NODE_A = 'a1'.repeat(32);
const NODE_B = 'b2'.repeat(32);
const SEED_A = 'c3'.repeat(32);
const SEED_B = 'd4'.repeat(32);
const PUB_A = 'e5'.repeat(32);
const PUB_B = 'f6'.repeat(32);
const ADMIN_KEY = 'cawala.admin.v1';

function reset() {
  memory.clear();
}

function entry(nodeId, seedHex, pubHex, { grantedAt, expiresAt, label = null, nodeAddr = null } = {}) {
  return {
    nodeId,
    adminSeedHex: seedHex,
    adminPubHex: pubHex,
    grantedAt,
    expiresAt,
    label,
    nodeAddr,
  };
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test('add/load round-trip (seed-free view)', () => {
  reset();
  const now = 1_700_000_000_000;
  const stored = addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000, label: 'parent A' }),
  );

  assert.deepEqual(stored, {
    nodeId: NODE_A,
    adminPubHex: PUB_A,
    scope: 'admin',
    grantedAt: now,
    expiresAt: now + 1000,
    label: 'parent A',
    nodeAddr: null,
  });

  const loaded = loadAdminEntries();
  assert.equal(loaded.length, 1);
  assert.deepEqual(loaded[0], stored);
  assert.equal(JSON.stringify(loaded).includes(SEED_A), false);
});

test('replace-on-same-nodeId keeps a single entry with the new values', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  addAdminEntry(entry(NODE_A, SEED_B, PUB_B, { grantedAt: now, expiresAt: now + 2000 }));

  const loaded = loadAdminEntries();
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].adminPubHex, PUB_B);
  assert.equal(loaded[0].expiresAt, now + 2000);
  assert.equal(Buffer.from(adminSeedBytes(NODE_A)).toString('hex'), SEED_B);
});

test('malformed storage yields [] and never throws', () => {
  reset();
  memory.setItem(ADMIN_KEY, '{not json');
  assert.deepEqual(loadAdminEntries(), []);
  assert.deepEqual(listAdminNodes(), []);
  assert.equal(activeAdminNode(), null);
  assert.equal(adminSeedBytes(NODE_A), null);

  memory.setItem(ADMIN_KEY, JSON.stringify({ v: 2, entries: [] }));
  assert.deepEqual(loadAdminEntries(), []);

  memory.setItem(ADMIN_KEY, JSON.stringify({ v: 1, entries: 'not-an-array' }));
  assert.deepEqual(loadAdminEntries(), []);

  // Invalid rows inside a valid envelope are dropped, not returned.
  memory.setItem(
    ADMIN_KEY,
    JSON.stringify({ v: 1, entries: [{ nodeId: 'short', adminSeedHex: SEED_A, adminPubHex: PUB_A }] }),
  );
  assert.deepEqual(loadAdminEntries(), []);
});

test('loadAdminEntries tolerates throwing storage', () => {
  const original = globalThis.localStorage;
  globalThis.localStorage = {
    getItem() {
      throw new Error('boom');
    },
    setItem() {},
    removeItem() {},
  };
  assert.deepEqual(loadAdminEntries(), []);
  globalThis.localStorage = original;
});

test('invalid hex / lifetime is rejected', () => {
  reset();
  const now = 1_700_000_000_000;
  assert.throws(
    () => addAdminEntry(entry('not-hex', SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1 })),
    /nodeId must be exactly 64 hex characters/,
  );
  assert.throws(
    () => addAdminEntry(entry(NODE_A, '00', PUB_A, { grantedAt: now, expiresAt: now + 1 })),
    /adminSeedHex must be exactly 64 hex characters/,
  );
  assert.throws(
    () => addAdminEntry(entry(NODE_A, SEED_A, 'zz', { grantedAt: now, expiresAt: now + 1 })),
    /adminPubHex must be exactly 64 hex characters/,
  );
  assert.throws(
    () => addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now })),
    /expiresAt must be greater than grantedAt/,
  );
});

test('activeAdminNode returns active entries and skips expired ones', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now - 10_000, expiresAt: now - 1 }));
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now - 1000, expiresAt: now + 1000 }));

  const active = activeAdminNode(now);
  assert.equal(active.nodeId, NODE_A);
  assert.equal(JSON.stringify(active).includes(SEED_A), false);

  // Once NODE_A expires, there is no active admin.
  assert.equal(activeAdminNode(now + 2000), null);

  const list = listAdminNodes(now);
  assert.deepEqual(
    list.map((e) => ({ nodeId: e.nodeId, active: e.active })),
    [
      { nodeId: NODE_B, active: false },
      { nodeId: NODE_A, active: true },
    ],
  );
});

test('findAdminNode matches case-insensitively and is seed-free', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  const found = findAdminNode(NODE_A.toUpperCase());
  assert.equal(found.nodeId, NODE_A);
  assert.equal(JSON.stringify(found).includes(SEED_A), false);
  assert.equal(findAdminNode(NODE_B), null);
});

test('listAdminNodes never includes the seed', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  const serialized = JSON.stringify(listAdminNodes(now));
  assert.equal(serialized.includes(SEED_A), false);
  assert.equal(serialized.includes('adminSeedHex'), false);
  assert.equal(serialized.includes(PUB_A), true);
});

test('nodeAddr round-trips through addAdminEntry/listAdminNodes', () => {
  reset();
  const now = 1_700_000_000_000;
  const stored = addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000, nodeAddr: '0.1.2' }),
  );
  assert.equal(stored.nodeAddr, '0.1.2');

  const listed = listAdminNodes(now);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].nodeAddr, '0.1.2');
  assert.equal(findAdminNode(NODE_A).nodeAddr, '0.1.2');
  assert.equal(JSON.stringify(listed).includes(SEED_A), false);

  // A bare root address is valid too.
  addAdminEntry(
    entry(NODE_B, SEED_B, PUB_B, { grantedAt: now, expiresAt: now + 1000, nodeAddr: '0' }),
  );
  assert.equal(findAdminNode(NODE_B).nodeAddr, '0');
});

test('invalid nodeAddr values are rejected', () => {
  reset();
  const now = 1_700_000_000_000;
  const base = { grantedAt: now, expiresAt: now + 1000 };
  const invalid = [
    '',
    '.',
    '0.',
    '.0',
    '0..1',
    '8',
    '08',
    '0.8',
    'a.b',
    '0.1.a',
    ' 0.1',
    '0.1 ',
  ];
  for (const nodeAddr of invalid) {
    assert.throws(
      () => addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { ...base, nodeAddr })),
      /nodeAddr must be a dotted octal address/,
      `expected ${JSON.stringify(nodeAddr)} to be rejected`,
    );
  }

  // Valid multi-level addresses do not throw.
  for (const nodeAddr of ['0', '7', '0.1.2', '7.7.7.7.7.7.7.7']) {
    addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { ...base, nodeAddr }));
  }
});

test('pre-existing stored entries without nodeAddr read back as null', () => {
  reset();
  const now = 1_700_000_000_000;
  // Simulate a v1 record written before nodeAddr existed (no key at all).
  memory.setItem(
    ADMIN_KEY,
    JSON.stringify({
      v: 1,
      entries: [
        {
          nodeId: NODE_A,
          adminSeedHex: SEED_A,
          adminPubHex: PUB_A,
          scope: 'admin',
          grantedAt: now,
          expiresAt: now + 1000,
          label: 'legacy',
        },
      ],
    }),
  );

  const loaded = loadAdminEntries();
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].nodeAddr, null);
  assert.equal(listAdminNodes(now)[0].nodeAddr, null);
  assert.equal(findAdminNode(NODE_A).nodeAddr, null);
  assert.equal(activeAdminNode(now).nodeAddr, null);
  assert.equal(Buffer.from(adminSeedBytes(NODE_A)).toString('hex'), SEED_A);
});

test('a malformed stored nodeAddr normalizes to null without dropping the entry', () => {
  reset();
  const now = 1_700_000_000_000;
  memory.setItem(
    ADMIN_KEY,
    JSON.stringify({
      v: 1,
      entries: [
        entry(NODE_A, SEED_A, PUB_A, {
          grantedAt: now,
          expiresAt: now + 1000,
          nodeAddr: '8.8.8',
        }),
      ],
    }),
  );

  const loaded = loadAdminEntries();
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].nodeAddr, null);
});

test('getAdminNodes-equivalent public surface never exposes seed material', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, {
      grantedAt: now,
      expiresAt: now + 1000,
      label: 'parent A',
      nodeAddr: '0.1.2',
    }),
  );

  // `api.getAdminNodes()` is a thin wrapper over `listAdminNodes()`; assert the
  // exact seed-free shape it forwards to the UI.
  const listed = listAdminNodes(now);
  const serialized = JSON.stringify(listed);
  assert.equal(serialized.includes(SEED_A), false);
  assert.equal(serialized.includes('adminSeedHex'), false);
  assert.deepEqual(Object.keys(listed[0]).sort(), [
    'active',
    'adminPubHex',
    'expiresAt',
    'grantedAt',
    'label',
    'nodeAddr',
    'nodeId',
    'scope',
  ]);
});

test('adminSeedBytes returns the exact 32 bytes', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));

  const bytes = adminSeedBytes(NODE_A);
  assert.ok(bytes instanceof Uint8Array);
  assert.equal(bytes.length, 32);
  assert.deepEqual(bytes, hexToBytes(SEED_A));
  assert.equal(adminSeedBytes(NODE_B), null);
});

test('removeAdminNode removes only the requested entry', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now, expiresAt: now + 1000 }));

  removeAdminNode(NODE_A);
  assert.equal(findAdminNode(NODE_A), null);
  assert.equal(findAdminNode(NODE_B).nodeId, NODE_B);
  assert.equal(loadAdminEntries().length, 1);
});

test('clearAllAdminEntries empties the store', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now, expiresAt: now + 1000 }));

  clearAllAdminEntries();
  assert.deepEqual(loadAdminEntries(), []);
  assert.deepEqual(listAdminNodes(), []);
  assert.equal(adminSeedBytes(NODE_A), null);
  assert.equal(memory.getItem(ADMIN_KEY), null);
});
