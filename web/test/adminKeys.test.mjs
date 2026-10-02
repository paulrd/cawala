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
  getSelectedAdminNode,
  selectedNodeId,
  selectAdminNode,
  adminSeedBytes,
  adminSeedState,
  addAdminEntry,
  applyAdminGrant,
  updateLastSeen,
  removeAdminNode,
  clearAllAdminEntries,
  unlockAdminSeed,
  lockAdminSeed,
  lockAllAdminSeeds,
  protectAdminSeed,
  unprotectAdminSeed,
  GRANT_SOURCE,
  SEED_KIND,
} = await import('../src/lib/adminKeys.js');

const { wrapSeed } = await import('../src/lib/adminSeedCrypto.js');

// ── Fixtures ─────────────────────────────────────────────────────────────────

const NODE_A = 'a1'.repeat(32);
const NODE_B = 'b2'.repeat(32);
const SEED_A = 'c3'.repeat(32);
const SEED_B = 'd4'.repeat(32);
const PUB_A = 'e5'.repeat(32);
const PUB_B = 'f6'.repeat(32);
const NODE_C = 'ab'.repeat(32);
const SEED_C = 'cd'.repeat(32);
const PUB_C = 'ef'.repeat(32);
const NODE_D = '12'.repeat(32);
const SEED_D = '34'.repeat(32);
const PUB_D = '56'.repeat(32);
const ADMIN_KEY = 'cawala.admin.v3';   // current store
const V2_KEY = 'cawala.admin.v2';      // P1/P2 store, migrated on read
const LEGACY_KEY = 'cawala.admin.v1';  // pre-scoped store, migrated on read

function reset() {
  memory.clear();
}

function entry(
  nodeId,
  seedHex,
  pubHex,
  { grantedAt, expiresAt, label = null, nodeAddr = null, scopes = null } = {},
) {
  return {
    nodeId,
    adminSeedHex: seedHex,
    adminPubHex: pubHex,
    grantedAt,
    expiresAt,
    label,
    nodeAddr,
    // `null` = "not stated" -> the store falls back to joins-only.
    scopes,
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
    scopes: ['joins'],
    seedKind: 'plain',
    seedProtected: false,
    grantSource: 'manual',
    grantedAt: now,
    expiresAt: now + 1000,
    label: 'parent A',
    nodeAddr: null,
    lastSeenStatus: null,
    lastSeenKind: null,
    lastSeenAddress: null,
    lastSeenAt: null,
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

test('the selection is explicit: activeAdminNode never falls back to another grant', () => {
  reset();
  const now = Date.now();
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now - 10_000, expiresAt: now + 60_000 }));
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now - 1000, expiresAt: now + 1000 }));

  // The first stored grant becomes the selection once, and only then.
  assert.equal(selectedNodeId(), NODE_B);
  assert.equal(activeAdminNode(now).nodeId, NODE_B);
  assert.equal(JSON.stringify(activeAdminNode(now)).includes(SEED_B), false);

  // `self` is a real selection: no implicit "use some other valid grant".
  selectAdminNode('self');
  assert.equal(selectedNodeId(), 'self');
  assert.equal(activeAdminNode(now), null);
  assert.equal(getSelectedAdminNode(now), null);
  assert.equal(activeAdminNode(now + 60_000), null);

  // Selecting an expired grant yields null rather than silently re-picking one.
  addAdminEntry(entry(NODE_C, SEED_C, PUB_C, { grantedAt: now - 10_000, expiresAt: now - 1 }));
  selectAdminNode(NODE_C);
  assert.equal(selectedNodeId(), NODE_C);
  assert.equal(activeAdminNode(now), null);
  assert.ok(getSelectedAdminNode(now), 'the expired grant is still listed, just inactive');

  const list = listAdminNodes(now);
  assert.deepEqual(
    list.map((e) => ({ nodeId: e.nodeId, active: e.active, selected: e.selected })),
    [
      { nodeId: NODE_B, active: true, selected: false },
      { nodeId: NODE_A, active: true, selected: false },
      { nodeId: NODE_C, active: false, selected: true },
    ],
  );
});

test('selectAdminNode validates its argument and persists the choice', () => {
  reset();
  const now = Date.now();
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));

  assert.equal(selectAdminNode('self'), 'self');
  assert.equal(selectedNodeId(), 'self');

  assert.equal(selectAdminNode(NODE_A.toUpperCase()), NODE_A.toLowerCase());
  assert.equal(selectedNodeId(), NODE_A);
  // Persisted: a fresh read sees the same selection.
  assert.equal(selectedNodeId(), NODE_A);
  assert.equal(activeAdminNode(now).nodeId, NODE_A);

  assert.throws(() => selectAdminNode('not-a-node-id'), /64 hex characters/);
  assert.throws(
    () => selectAdminNode('b'.repeat(64)),
    /no stored admin key for that node id/,
  );
  assert.equal(selectedNodeId(), NODE_A, 'a rejected selection leaves the old one in place');
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
  const now = Date.now();
  // Simulate a v1 record written before nodeAddr existed (no key at all).
  memory.setItem(
    LEGACY_KEY,
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
    LEGACY_KEY,
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
    'grantSource',
    'grantedAt',
    'label',
    'lastSeenAddress',
    'lastSeenAt',
    'lastSeenKind',
    'lastSeenStatus',
    'nodeAddr',
    'nodeId',
    'scope',
    'scopes',
    'seedKind',
    'seedProtected',
    'selected',
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

// ── v1 → v2 migration ───────────────────────────────────────────────────────

test('a stored v1 envelope migrates to v3 on first read', () => {
  reset();
  const now = Date.now();
  memory.setItem(
    LEGACY_KEY,
    JSON.stringify({
      v: 1,
      entries: [
        {
          nodeId: NODE_A,
          adminSeedHex: SEED_A,
          adminPubHex: PUB_A,
          scope: 'admin',
          grantedAt: now - 1000,
          expiresAt: now + 1000,
          label: 'legacy parent',
        },
      ],
    }),
  );
  assert.equal(memory.getItem(ADMIN_KEY), null, 'nothing stored at the v3 key yet');

  const loaded = loadAdminEntries(now);
  assert.equal(loaded.length, 1);

  // Migrated envelope: v3, seed intact and plaintext, legacy keys retired.
  const raw = JSON.parse(memory.getItem(ADMIN_KEY));
  assert.equal(raw.v, 3);
  assert.equal(raw.entries.length, 1);
  assert.equal(raw.entries[0].adminSeedHex, SEED_A);
  assert.equal(raw.entries[0].seedKind, 'plain');
  assert.equal(memory.getItem(LEGACY_KEY), null);
  assert.equal(loaded[0].label, 'legacy parent');
  assert.equal(Buffer.from(adminSeedBytes(NODE_A)).toString('hex'), SEED_A);

  // Migration records an explicit selection instead of leaving it implicit.
  assert.equal(selectedNodeId(), NODE_A);
  assert.equal(activeAdminNode(now).nodeId, NODE_A);
});

test('a migrated v1 grant stays joins-only and is never silently widened', () => {
  reset();
  const now = Date.now();
  memory.setItem(
    LEGACY_KEY,
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
        },
      ],
    }),
  );

  assert.deepEqual(loadAdminEntries(now)[0].scopes, ['joins']);
  assert.deepEqual(
    JSON.parse(memory.getItem(ADMIN_KEY)).entries[0].scopes,
    ['joins'],
    'the migrated record itself is joins-only',
  );

  // A v1 record is never widened on read, even by a later v3 writer.
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now, expiresAt: now + 1000 }));
  assert.deepEqual(findAdminNode(NODE_B).scopes, ['joins'], 'omitted scopes default to joins');

  // Unknown scope names fall back to joins-only rather than being dropped
  // into a broader grant; known ones are kept as given.
  addAdminEntry(entry(NODE_C, SEED_C, PUB_C, {
    grantedAt: now,
    expiresAt: now + 1000,
    scopes: ['bogus', 'also-bogus'],
  }));
  addAdminEntry(entry(NODE_D, SEED_D, PUB_D, {
    grantedAt: now,
    expiresAt: now + 1000,
    scopes: ['joins', 'topology'],
  }));
  assert.deepEqual(findAdminNode(NODE_C).scopes, ['joins']);
  assert.deepEqual(findAdminNode(NODE_D).scopes, ['joins', 'topology']);
  // Seed still never leaves the store through any public view.
  for (const id of [NODE_B, NODE_C, NODE_D]) {
    assert.equal(findAdminNode(id).adminSeedHex, undefined);
  }
});

test('a corrupt v3 store falls back through v2 to the v1 key instead of losing the grants', () => {
  reset();
  const now = Date.now();
  memory.setItem(ADMIN_KEY, '{not json');
  memory.setItem(
    LEGACY_KEY,
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
        },
      ],
    }),
  );

  assert.equal(loadAdminEntries(now).length, 1);
  const repaired = JSON.parse(memory.getItem(ADMIN_KEY));
  assert.equal(repaired.v, 3, 'the corrupt payload is replaced with a valid one');
  assert.equal(repaired.entries[0].nodeId, NODE_A);
  assert.equal(memory.getItem(LEGACY_KEY), null, 'the legacy key is retired');
  assert.equal(memory.getItem(V2_KEY), null, 'the v2 key is retired too');
});

// ── Probe memory ────────────────────────────────────────────────────────────

test('updateLastSeen records probe results and leaves other rows alone', () => {
  reset();
  const now = Date.now();
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now, expiresAt: now + 1000 }));

  assert.equal(findAdminNode(NODE_A).lastSeenAt, null, 'never probed');

  updateLastSeen(NODE_A, { status: 'active', kind: 'internal', address: '0.3.1', at: now + 5 });
  const seen = findAdminNode(NODE_A);
  assert.equal(seen.lastSeenStatus, 'active');
  assert.equal(seen.lastSeenKind, 'internal');
  assert.equal(seen.lastSeenAddress, '0.3.1');
  assert.equal(seen.lastSeenAt, now + 5);
  assert.equal(findAdminNode(NODE_B).lastSeenAt, null, 'other rows untouched');

  // A partial update never erases what a better probe already saw.
  updateLastSeen(NODE_A, { status: 'unreachable' });
  assert.equal(findAdminNode(NODE_A).lastSeenKind, 'internal');
  assert.equal(findAdminNode(NODE_A).lastSeenStatus, 'unreachable');
  assert.equal(findAdminNode(NODE_A).lastSeenAt, now + 5);

  // A `null` timestamp stays null rather than collapsing to 0 (1970).
  updateLastSeen(NODE_B, { at: null });
  assert.equal(findAdminNode(NODE_B).lastSeenAt, null);
  assert.equal(loadAdminEntries()[1].lastSeenAt, null);
});

// ── Selection follow-through ────────────────────────────────────────────────

test('removing the selected node re-points the selection instead of stranding it', () => {
  reset();
  const now = Date.now();
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now - 1000, expiresAt: now + 1000 }));
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now - 500, expiresAt: now + 60_000 }));
  assert.equal(selectedNodeId(), NODE_A);

  removeAdminNode(NODE_A);
  assert.equal(selectedNodeId(), NODE_B, 'falls back to the other active grant');
  assert.equal(activeAdminNode(now).nodeId, NODE_B);

  removeAdminNode(NODE_B);
  assert.equal(selectedNodeId(), 'self', 'no grants left: this browser is the target');
  assert.equal(activeAdminNode(now), null);
});

test('clearing every grant leaves no selection, which the API resolves to self', () => {
  reset();
  const now = Date.now();
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  assert.equal(selectedNodeId(), NODE_A);

  clearAllAdminEntries();
  // No envelope at all: `selectedNodeId()` is null and api.js falls back to
  // `selectedNodeId() ?? SELF`, i.e. this browser is the target again.
  assert.equal(selectedNodeId(), null);
  assert.equal(activeAdminNode(now), null);
  assert.deepEqual(loadAdminEntries(), []);
});

// ── Verified grant application (applyAdminGrant) ────────────────────────────

test('a locally generated entry defaults grantSource to manual', () => {
  reset();
  const now = 1_700_000_000_000;
  const stored = addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  assert.equal(stored.grantSource, GRANT_SOURCE.MANUAL);
  assert.equal(findAdminNode(NODE_A).grantSource, GRANT_SOURCE.MANUAL);
});

test('a migrated v1 row defaults grantSource to manual', () => {
  reset();
  const now = Date.now();
  memory.setItem(
    LEGACY_KEY,
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
        },
      ],
    }),
  );
  assert.equal(loadAdminEntries(now)[0].grantSource, GRANT_SOURCE.MANUAL);
});

test('applyAdminGrant requires an existing entry', () => {
  reset();
  const now = 1_700_000_000_000;
  assert.throws(
    () => applyAdminGrant(NODE_A, { scopes: ['joins'], grantedAt: now, expiresAt: now + 1000 }),
    /generate a key for this node first/,
  );
});

test('applyAdminGrant rejects empty and unknown scopes without falling back to joins', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));

  assert.throws(
    () => applyAdminGrant(NODE_A, { scopes: [], grantedAt: now, expiresAt: now + 2000 }),
    /at least one scope/,
  );
  assert.throws(
    () => applyAdminGrant(NODE_A, { scopes: ['bogus'], grantedAt: now, expiresAt: now + 2000 }),
    /Unknown admin scope/,
  );
  assert.throws(
    () => applyAdminGrant(NODE_A, { scopes: ['joins', 'nope'], grantedAt: now, expiresAt: now + 2000 }),
    /Unknown admin scope/,
  );

  // The entry was not touched: still the provisional joins-only grant.
  const after = findAdminNode(NODE_A);
  assert.deepEqual(after.scopes, ['joins']);
  assert.equal(after.grantSource, GRANT_SOURCE.MANUAL);
  assert.equal(after.expiresAt, now + 1000);
});

test('applyAdminGrant replaces scopes/TTL/label, marks bundle, and preserves the rest', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, {
      grantedAt: now,
      expiresAt: now + 1000,
      label: 'provisional',
      nodeAddr: '0.1.2',
    }),
  );
  addAdminEntry(entry(NODE_B, SEED_B, PUB_B, { grantedAt: now - 10_000, expiresAt: now + 60_000 }));
  // NODE_A was the first entry, so it is the selection.
  assert.equal(selectedNodeId(), NODE_A);
  updateLastSeen(NODE_A, { status: 'active', kind: 'internal', address: '0.3.1', at: now + 5 });

  const expiresAt = now + 30 * 24 * 3600 * 1000;
  const applied = applyAdminGrant(NODE_A, {
    scopes: ['topology', 'joins'],
    grantedAt: now,
    expiresAt,
    label: 'operator grant',
  });

  assert.deepEqual(applied.scopes, ['topology', 'joins'], 'order comes from the bundle, not joins-first');
  assert.equal(applied.grantedAt, now);
  assert.equal(applied.expiresAt, expiresAt);
  assert.equal(applied.label, 'operator grant');
  assert.equal(applied.grantSource, GRANT_SOURCE.BUNDLE);

  // Seed/public key/address/probe memory/selection survive.
  assert.equal(Buffer.from(adminSeedBytes(NODE_A)).toString('hex'), SEED_A);
  assert.equal(findAdminNode(NODE_A).adminPubHex, PUB_A);
  assert.equal(findAdminNode(NODE_A).nodeAddr, '0.1.2');
  assert.equal(findAdminNode(NODE_A).lastSeenStatus, 'active');
  assert.equal(findAdminNode(NODE_A).lastSeenKind, 'internal');
  assert.equal(selectedNodeId(), NODE_A, 'importing a bundle never retargets the console');
  assert.equal(activeAdminNode(now).nodeId, NODE_A);

  // The other entry is untouched.
  assert.deepEqual(findAdminNode(NODE_B).scopes, ['joins']);
  assert.equal(findAdminNode(NODE_B).grantSource, GRANT_SOURCE.MANUAL);
});

test('applyAdminGrant dedupes scopes and requires expiresAt > grantedAt', () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));

  const applied = applyAdminGrant(NODE_A, {
    scopes: ['value', 'value', 'topology'],
    grantedAt: now,
    expiresAt: now + 1000,
  });
  assert.deepEqual(applied.scopes, ['value', 'topology']);

  assert.throws(
    () => applyAdminGrant(NODE_A, { scopes: ['joins'], grantedAt: now, expiresAt: now }),
    /expiresAt must be greater than grantedAt/,
  );
  assert.throws(
    () => applyAdminGrant(NODE_A, { scopes: ['joins'], grantedAt: 'nope', expiresAt: now }),
    /grantedAt must be a finite timestamp/,
  );
});

// ── P6: v3 store + seed protection ──────────────────────────────────────────

test('a stored v2 envelope migrates to v3 with plaintext rows', () => {
  reset();
  const now = 1_700_000_000_000;
  memory.setItem(
    V2_KEY,
    JSON.stringify({
      v: 2,
      selected: NODE_A,
      entries: [entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 })],
    }),
  );
  assert.equal(memory.getItem(ADMIN_KEY), null);

  const loaded = loadAdminEntries(now);
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].seedKind, 'plain');
  assert.equal(loaded[0].seedProtected, false);

  const raw = JSON.parse(memory.getItem(ADMIN_KEY));
  assert.equal(raw.v, 3);
  assert.equal(raw.entries[0].adminSeedHex, SEED_A);
  assert.equal(memory.getItem(V2_KEY), null, 'the v2 key is retired');
});

test('protectAdminSeed wraps the seed and locks it from bytes until unlock', async () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000, scopes: ['value'] }),
  );
  assert.equal(adminSeedState(NODE_A), 'plain');
  assert.deepEqual(adminSeedBytes(NODE_A), hexToBytes(SEED_A));

  await protectAdminSeed(NODE_A, 'passphrase');
  // Just wrapped: cached for this session.
  assert.equal(adminSeedState(NODE_A), 'unlocked');
  assert.deepEqual(adminSeedBytes(NODE_A), hexToBytes(SEED_A));

  // Seed-free public views expose only the protection status.
  const publicEntry = findAdminNode(NODE_A);
  assert.equal(publicEntry.seedProtected, true);
  assert.equal(publicEntry.seedKind, SEED_KIND.WRAPPED);
  assert.equal(publicEntry.adminSeedHex, undefined);
  assert.equal(publicEntry.seedWrapped, undefined);
  assert.equal(JSON.stringify(publicEntry).includes(SEED_A), false);

  // The persisted store no longer contains the plaintext seed.
  const onDisk = memory.getItem(ADMIN_KEY);
  assert.equal(onDisk.includes(SEED_A), false);
  assert.equal(onDisk.includes('adminSeedHex'), false);
  assert.equal(JSON.parse(onDisk).entries[0].seedKind, SEED_KIND.WRAPPED);

  // Lock: bytes become unavailable; a wrong passphrase stays rejected.
  lockAdminSeed(NODE_A);
  assert.equal(adminSeedState(NODE_A), 'locked');
  assert.equal(adminSeedBytes(NODE_A), null);
  await assert.rejects(() => unlockAdminSeed(NODE_A, 'wrong'), /Incorrect passphrase/);
  assert.equal(adminSeedState(NODE_A), 'locked');

  // Correct unlock restores the bytes.
  assert.equal(await unlockAdminSeed(NODE_A, 'passphrase'), true);
  assert.equal(adminSeedState(NODE_A), 'unlocked');
  assert.deepEqual(adminSeedBytes(NODE_A), hexToBytes(SEED_A));
});

test('lockAllAdminSeeds and clearAllAdminEntries clear the unlock cache', async () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000, scopes: ['value'] }),
  );
  await protectAdminSeed(NODE_A, 'passphrase');
  assert.equal(adminSeedState(NODE_A), 'unlocked');

  lockAllAdminSeeds();
  assert.equal(adminSeedState(NODE_A), 'locked');

  await unlockAdminSeed(NODE_A, 'passphrase');
  assert.equal(adminSeedState(NODE_A), 'unlocked');
  clearAllAdminEntries();
  assert.equal(adminSeedState(NODE_A), 'absent');
  assert.equal(adminSeedBytes(NODE_A), null);
});

test('unprotectAdminSeed requires an unlocked seed', async () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000, scopes: ['value'] }),
  );
  await protectAdminSeed(NODE_A, 'passphrase');
  lockAdminSeed(NODE_A);

  assert.throws(() => unprotectAdminSeed(NODE_A), /Unlock this value key/);
  assert.equal(adminSeedState(NODE_A), 'locked');

  await unlockAdminSeed(NODE_A, 'passphrase');
  unprotectAdminSeed(NODE_A);
  assert.equal(adminSeedState(NODE_A), 'plain');
  assert.deepEqual(adminSeedBytes(NODE_A), hexToBytes(SEED_A));
  assert.equal(findAdminNode(NODE_A).seedProtected, false);
});

test('protectAdminSeed refuses a non-value entry', async () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000 }));
  await assert.rejects(() => protectAdminSeed(NODE_A, 'passphrase'), /Only value-scoped/);
  assert.equal(adminSeedState(NODE_A), 'plain');
  assert.equal(findAdminNode(NODE_A).seedProtected, false);
});

test('removeAdminNode clears the session-unlocked seed', async () => {
  reset();
  const now = 1_700_000_000_000;
  addAdminEntry(
    entry(NODE_A, SEED_A, PUB_A, { grantedAt: now, expiresAt: now + 1000, scopes: ['value'] }),
  );
  await protectAdminSeed(NODE_A, 'passphrase');
  assert.equal(adminSeedState(NODE_A), 'unlocked');

  removeAdminNode(NODE_A);
  assert.equal(adminSeedState(NODE_A), 'absent');

  // Re-add the same node with a different wrapped seed: it must read locked,
  // proving the old unlocked cache entry was dropped.
  const wrapped = await wrapSeed(SEED_B, 'other passphrase', NODE_A);
  memory.setItem(
    ADMIN_KEY,
    JSON.stringify({
      v: 3,
      selected: NODE_A,
      entries: [
        {
          nodeId: NODE_A,
          seedWrapped: wrapped,
          adminPubHex: PUB_A,
          seedKind: 'pbkdf2-aes-gcm',
          seedProtected: true,
          scopes: ['value'],
          grantedAt: now,
          expiresAt: now + 1000,
        },
      ],
    }),
  );
  assert.equal(adminSeedState(NODE_A), 'locked');
});

test('a wrapped row survives public accessors but a malformed wrap is dropped', async () => {
  reset();
  const now = 1_700_000_000_000;
  const wrapped = await wrapSeed(SEED_A, 'passphrase', NODE_A);
  memory.setItem(
    ADMIN_KEY,
    JSON.stringify({
      v: 3,
      selected: NODE_A,
      entries: [
        {
          nodeId: NODE_A,
          seedWrapped: wrapped,
          adminPubHex: PUB_A,
          seedKind: 'pbkdf2-aes-gcm',
          seedProtected: true,
          grantedAt: now,
          expiresAt: now + 1000,
        },
      ],
    }),
  );
  const loaded = loadAdminEntries(now);
  assert.equal(loaded.length, 1, 'a wrapped row is never dropped');
  assert.equal(loaded[0].seedProtected, true);
  assert.equal(loaded[0].seedKind, 'pbkdf2-aes-gcm');
  assert.equal(adminSeedState(NODE_A), 'locked');
  assert.equal(adminSeedBytes(NODE_A), null);

  // A structurally invalid wrap drops just that row.
  memory.setItem(
    ADMIN_KEY,
    JSON.stringify({
      v: 3,
      selected: NODE_A,
      entries: [
        {
          nodeId: NODE_A,
          seedWrapped: { kdf: {}, aead: {}, ct: 'x' },
          adminPubHex: PUB_A,
          grantedAt: now,
          expiresAt: now + 1000,
        },
      ],
    }),
  );
  assert.deepEqual(loadAdminEntries(now), []);
});
