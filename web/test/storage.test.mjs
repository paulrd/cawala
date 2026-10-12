import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  STORAGE_CLASS,
  STORAGE_KEYS,
  TOFU_ANCHOR_FIELDS,
  STORAGE_CLASSIFICATION,
  classifyStorageKey,
  readScopedBlob,
  writeScopedBlob,
  restoreBlobs,
} from '../src/lib/storage.js';

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

function b64(text) {
  return Buffer.from(text).toString('base64');
}

// ── Classification ───────────────────────────────────────────────────────────

test('identity key is authoritative-local', () => {
  assert.equal(
    classifyStorageKey(STORAGE_KEYS.IDENTITY),
    STORAGE_CLASS.AUTHORITATIVE_LOCAL,
  );
});

test('state/ledger blobs (scoped and legacy) are best-effort cache', () => {
  assert.equal(classifyStorageKey(STORAGE_KEYS.STATE), STORAGE_CLASS.BEST_EFFORT_CACHE);
  assert.equal(classifyStorageKey(`${STORAGE_KEYS.STATE}:abc123`), STORAGE_CLASS.BEST_EFFORT_CACHE);
  assert.equal(classifyStorageKey(STORAGE_KEYS.LEDGER), STORAGE_CLASS.BEST_EFFORT_CACHE);
  assert.equal(classifyStorageKey(`${STORAGE_KEYS.LEDGER}:abc123`), STORAGE_CLASS.BEST_EFFORT_CACHE);
});

test('the ledger quarantine backup is authoritative-local', () => {
  assert.equal(
    classifyStorageKey(STORAGE_KEYS.LEDGER_BACKUP),
    STORAGE_CLASS.AUTHORITATIVE_LOCAL,
  );
  assert.equal(
    classifyStorageKey(`${STORAGE_KEYS.LEDGER_BACKUP}:abc123`),
    STORAGE_CLASS.AUTHORITATIVE_LOCAL,
  );
});

test('recovery / admin-policy / value-pending are non-authoritative local', () => {
  for (const key of [STORAGE_KEYS.RECOVERY, STORAGE_KEYS.ADMIN_POLICY, STORAGE_KEYS.VALUE_PENDING]) {
    assert.equal(classifyStorageKey(key), STORAGE_CLASS.NON_AUTHORITATIVE_LOCAL);
  }
});

test('unknown and empty keys classify as null', () => {
  assert.equal(classifyStorageKey('cawala.unknown.v1'), null);
  assert.equal(classifyStorageKey(''), null);
  assert.equal(classifyStorageKey(undefined), null);
});

test('the classification table covers every documented key', () => {
  const documented = new Set(STORAGE_CLASSIFICATION.map((row) => row.key));
  for (const key of Object.values(STORAGE_KEYS)) {
    // TOFU anchors are fields, not keys, and are checked separately.
    assert.ok(documented.has(key), `missing classification row for ${key}`);
  }
  for (const anchor of TOFU_ANCHOR_FIELDS) {
    const row = STORAGE_CLASSIFICATION.find((r) => r.key === anchor);
    assert.ok(row, `missing classification row for ${anchor}`);
    assert.equal(row.class, STORAGE_CLASS.AUTHORITATIVE_LOCAL);
    assert.equal(row.storage, STORAGE_KEYS.LEDGER);
  }
});

// ── readScopedBlob (best-effort) ─────────────────────────────────────────────

test('readScopedBlob reads the scoped key, then falls back to legacy', () => {
  const store = new MemoryStorage();
  store.setItem(`${STORAGE_KEYS.STATE}:node-a`, b64('scoped-bytes'));
  // A different node id falls through to the legacy un-suffixed key.
  store.setItem(STORAGE_KEYS.STATE, b64('legacy-bytes'));

  assert.equal(
    new TextDecoder().decode(readScopedBlob(STORAGE_KEYS.STATE, 'node-a', { store })),
    'scoped-bytes',
  );
  assert.equal(
    new TextDecoder().decode(readScopedBlob(STORAGE_KEYS.STATE, 'node-b', { store })),
    'legacy-bytes',
  );
});

test('readScopedBlob returns null for missing and corrupt blobs without throwing', () => {
  const store = new MemoryStorage();
  assert.doesNotThrow(() => readScopedBlob(STORAGE_KEYS.LEDGER, 'node-a', { store }));
  assert.equal(readScopedBlob(STORAGE_KEYS.LEDGER, 'node-a', { store }), null);

  store.setItem(`${STORAGE_KEYS.LEDGER}:node-a`, 'not-valid-base64!!');
  let decoded = null;
  assert.doesNotThrow(() => {
    decoded = readScopedBlob(STORAGE_KEYS.LEDGER, 'node-a', { store });
  });
  assert.equal(decoded, null);
});

test('readScopedBlob tolerates a throwing storage', () => {
  const throwing = {
    getItem() {
      throw new Error('boom');
    },
  };
  const warnings = [];
  assert.equal(
    readScopedBlob(STORAGE_KEYS.STATE, 'node-a', {
      store: throwing,
      onWarn: (kind) => warnings.push(kind),
    }),
    null,
  );
  assert.deepEqual(warnings, ['read']);
});

// ── writeScopedBlob (quarantine) ─────────────────────────────────────────────

test('writeScopedBlob writes an identity-scoped base64 blob', () => {
  const store = new MemoryStorage();
  const bytes = new Uint8Array([1, 2, 3, 4]);
  assert.equal(writeScopedBlob(STORAGE_KEYS.LEDGER_BACKUP, 'node-a', bytes, { store }), true);
  assert.equal(
    store.getItem(`${STORAGE_KEYS.LEDGER_BACKUP}:node-a`),
    Buffer.from(bytes).toString('base64'),
  );
});

test('writeScopedBlob never throws and reports failure', () => {
  const throwing = {
    setItem() {
      throw new Error('quota');
    },
  };
  const warnings = [];
  assert.equal(
    writeScopedBlob(STORAGE_KEYS.LEDGER_BACKUP, 'node-a', new Uint8Array([1]), {
      store: throwing,
      onWarn: (kind) => warnings.push(kind),
    }),
    false,
  );
  assert.deepEqual(warnings, ['write']);
  // Nothing to write is a clean false, too.
  assert.equal(
    writeScopedBlob(STORAGE_KEYS.LEDGER_BACKUP, 'node-a', new Uint8Array([]), { store: throwing }),
    false,
  );
});

test('a quarantined backup survives an overwrite of the live ledger blob', () => {
  const store = new MemoryStorage();
  const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  assert.equal(writeScopedBlob(STORAGE_KEYS.LEDGER_BACKUP, 'node-a', original, { store }), true);
  // The live blob is later overwritten with a fresh export...
  assert.equal(
    writeScopedBlob(STORAGE_KEYS.LEDGER, 'node-a', new Uint8Array([2]), { store }),
    true,
  );
  // ...while the quarantine backup (a different key) keeps the original bytes.
  assert.equal(
    new TextDecoder().decode(readScopedBlob(STORAGE_KEYS.LEDGER_BACKUP, 'node-a', { store })),
    new TextDecoder().decode(original),
  );
  assert.equal(store.getItem(`${STORAGE_KEYS.LEDGER}:node-a`), Buffer.from([2]).toString('base64'));
});

// ── restoreBlobs (boot resilience) ───────────────────────────────────────────

test('restoreBlobs with missing blobs is a no-op and never throws', () => {
  const calls = [];
  const node = {
    import_state: () => calls.push('state'),
    import_ledger_state: () => calls.push('ledger'),
  };
  const result = restoreBlobs(node, { stateBytes: null, ledgerBytes: null });
  assert.deepEqual(result, { stateImported: false, ledgerImported: false });
  assert.deepEqual(calls, []);
});

test('restoreBlobs imports present blobs', () => {
  const node = {
    import_state() {},
    import_ledger_state() {},
  };
  const result = restoreBlobs(node, {
    stateBytes: new Uint8Array([1, 2, 3]),
    ledgerBytes: new Uint8Array([4, 5]),
  });
  assert.deepEqual(result, { stateImported: true, ledgerImported: true });
});

test('a corrupt blob does not block boot: import errors are swallowed', () => {
  const node = {
    import_state() {
      throw new Error('bad postcard state');
    },
    import_ledger_state() {
      throw new Error('bad postcard ledger');
    },
  };
  const warnings = [];
  let result;
  assert.doesNotThrow(() => {
    result = restoreBlobs(node, {
      stateBytes: new Uint8Array([0xff]),
      ledgerBytes: new Uint8Array([0xee]),
      onWarn: (kind) => warnings.push(kind),
    });
  });
  assert.deepEqual(result, { stateImported: false, ledgerImported: false });
  assert.deepEqual(warnings, ['state', 'ledger']);
});

test('restoreBlobs skips a node without the import method', () => {
  const result = restoreBlobs(
    {},
    { stateBytes: new Uint8Array([1]), ledgerBytes: new Uint8Array([2]) },
  );
  assert.deepEqual(result, { stateImported: false, ledgerImported: false });
});
