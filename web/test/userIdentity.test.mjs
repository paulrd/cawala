import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * User-identity surface tests (R3, identity UI lane → P2b-web).
 *
 * Exercises the exact API the identity UI calls — imported from `api.js`, the
 * app's single boundary — plus the reactive store sync. Address/secret
 * derivation now runs the REAL wasm engine, which `api.js` injects into the
 * facade after wasm init. Under `node --test` there is no wasm, so these tests
 * inject a deterministic mock backend via `setIdentityBackend` and pin the
 * contract the real backend must satisfy.
 *
 * Shims the rune primitive, storage and window before `api.js` loads,
 * matching `apiGetters.test.mjs`.
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
// No `isSecureContext`, no `PublicKeyCredential`: passkeys unavailable, like
// a `file://` or plain-http page.
globalThis.window = { localStorage: memory };
globalThis.$state = (value) => value;

// ── Mock crypto backend (stands in for the wasm UserIdentity) ──────────────

async function _sha256Hex(text) {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)),
  );
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function _bytesFromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Deterministic, correctly-shaped (but non-cryptographic) mock backend. */
const mockBackend = {
  async deriveAddress(mnemonic, passphrase) {
    const hex = await _sha256Hex(`addr:${mnemonic}:${passphrase}`);
    return `0x${hex.slice(0, 40)}`;
  },
  async secretBytes(mnemonic, passphrase) {
    return (await _bytesFromHex(await _sha256Hex(`secret:${mnemonic}:${passphrase}`))).slice(0, 32);
  },
  async transportSeed(mnemonic, passphrase) {
    return (await _bytesFromHex(await _sha256Hex(`transport:${mnemonic}:${passphrase}`))).slice(0, 32);
  },
};

const {
  isPasskeyAvailable,
  getUserIdentity,
  getEthAddress,
  generateMnemonic,
  validateMnemonic,
  previewIdentity,
  createIdentity,
  restoreIdentity,
  hasPasskey,
  enrollPasskey,
  unlockWithPasskey,
  removePasskey,
  refreshUserIdentity,
  wipeIdentity,
  __bootRealNodeForTest,
  getEthRegistrationStatus,
  isMockMode,
  InvalidMnemonicError,
  PasskeyUnavailableError,
  IdentityBackendUnavailableError,
  MNEMONIC_ERRORS,
} = await import('../src/lib/api.js');
const { userIdentityState } = await import('../src/lib/stores.svelte.js');
const {
  STORAGE_KEYS,
  classifyStorageKey,
  STORAGE_CLASS,
} = await import('../src/lib/storage.js');
const {
  USER_IDENTITY_BACKEND_READY,
  PASSKEY_BACKEND_READY,
  USER_IDENTITY_VERSION,
  setIdentityBackend,
  getIdentitySecretBytes,
} = await import('../src/lib/userIdentity.js');

// Inject the mock before any derivation-dependent test runs.
setIdentityBackend(mockBackend);

const GOOD_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

test('the real crypto backend is connected; passkeys remain deferred', () => {
  assert.equal(USER_IDENTITY_BACKEND_READY, true);
  assert.equal(PASSKEY_BACKEND_READY, false);
});

test('fresh device: no identity, passkeys unavailable outside a secure context', () => {
  assert.equal(isPasskeyAvailable(), false);
  const status = getUserIdentity();
  assert.equal(status.established, false);
  assert.equal(status.address, null);
  assert.equal(status.source, null);
  assert.equal(status.passkeyEnrolled, false);
  assert.equal(getEthAddress(), null);
  assert.equal(getIdentitySecretBytes(), null);
  assert.equal(memory.getItem(STORAGE_KEYS.USER_IDENTITY), null);
});

test('the derived-secret record is classified authoritative-local', () => {
  assert.equal(
    classifyStorageKey(STORAGE_KEYS.USER_IDENTITY),
    STORAGE_CLASS.AUTHORITATIVE_LOCAL,
  );
});

test('validateMnemonic surfaces stable, word-level error codes', async () => {
  assert.equal((await validateMnemonic('')).error.code, MNEMONIC_ERRORS.EMPTY);
  assert.equal((await validateMnemonic('abandon about')).error.code, MNEMONIC_ERRORS.WORD_COUNT);
  const unknown = await validateMnemonic(`${'abandon '.repeat(11)}wibble`.trim());
  assert.equal(unknown.error.code, MNEMONIC_ERRORS.UNKNOWN_WORD);
  assert.equal(unknown.error.wordIndex, 11);
  const badChecksum = await validateMnemonic(`${'abandon '.repeat(11)}art`.trim());
  assert.equal(badChecksum.error.code, MNEMONIC_ERRORS.CHECKSUM);
  assert.equal((await validateMnemonic(GOOD_12)).ok, true);
});

test('generateMnemonic returns a phrase that validates', async () => {
  const mnemonic = await generateMnemonic();
  assert.equal(mnemonic.split(' ').length, 12);
  assert.equal((await validateMnemonic(mnemonic)).ok, true);
});

test('previewIdentity derives a real, deterministic address (no preview flag)', async () => {
  const first = await previewIdentity(GOOD_12);
  const second = await previewIdentity(GOOD_12);
  assert.match(first.address, ADDRESS_RE);
  assert.equal(first.preview, false);
  assert.equal(first.address, second.address, 'same phrase + passphrase → same address');

  const wrapped = await previewIdentity(GOOD_12, 'a different passphrase');
  assert.notEqual(wrapped.address, first.address, 'passphrase changes the account');
});

test('previewIdentity forwards the backend address unchanged', async () => {
  // Pins the facade→backend contract: the facade must not transform the
  // address the wasm engine returns.
  const expected = await mockBackend.deriveAddress(GOOD_12, '');
  assert.equal((await previewIdentity(GOOD_12)).address, expected);
});

test('previewIdentity rejects a bad phrase with InvalidMnemonicError', async () => {
  await assert.rejects(
    () => previewIdentity('not a phrase'),
    (err) => err instanceof InvalidMnemonicError && err.code === MNEMONIC_ERRORS.WORD_COUNT,
  );
});

test('createIdentity: generates, derives, persists the secret, and syncs the store', async () => {
  const { status, inputMnemonic } = await createIdentity();
  assert.equal(status.established, true);
  assert.equal(status.source, 'created');
  assert.match(status.address, ADDRESS_RE);
  assert.equal(status.preview, false);
  assert.equal(typeof inputMnemonic, 'string');
  assert.equal(inputMnemonic.split(' ').length, 12);
  assert.equal((await validateMnemonic(inputMnemonic)).ok, true);

  // The API refreshes the reactive view it publishes to components.
  assert.equal(userIdentityState.established, true);
  assert.equal(userIdentityState.address, status.address);
  assert.equal(getEthAddress(), status.address);

  // Persisted under the documented key — the derived secret, never the phrase.
  const raw = memory.getItem(STORAGE_KEYS.USER_IDENTITY);
  assert.ok(raw, 'record persisted');
  assert.equal(raw.includes(inputMnemonic), false, 'mnemonic never persisted');
  const record = JSON.parse(raw);
  assert.equal(record.address, status.address);
  assert.equal(record.v, USER_IDENTITY_VERSION);
  assert.match(record.secret, /^[0-9a-f]{64}$/, 'derived secp256k1 secret persisted as hex');
  assert.equal('mnemonic' in record, false);
  assert.equal('seed' in record, false);

  // The secret is readable as raw bytes and matches the record.
  const secret = getIdentitySecretBytes();
  assert.ok(secret instanceof Uint8Array);
  assert.equal(secret.length, 32);
  assert.equal(hex(secret), record.secret);
});

test('createIdentity persists the mnemonic-derived transport seed (not the raw mnemonic)', async () => {
  await clearViaRemove();
  const { inputMnemonic } = await createIdentity();
  const storedSeedHex = memory.getItem(STORAGE_KEYS.IDENTITY);
  assert.match(storedSeedHex, /^[0-9a-f]{64}$/, 'transport seed stored as 32-byte hex');
  const expected = await mockBackend.transportSeed(inputMnemonic, '');
  assert.equal(storedSeedHex, hex(expected), 'stored transport seed is the mnemonic-derived one');
  assert.equal(storedSeedHex.includes(inputMnemonic), false);
});

test('refreshUserIdentity republishes the stored view after external changes', () => {
  userIdentityState.established = false;
  userIdentityState.address = null;
  refreshUserIdentity();
  assert.equal(userIdentityState.established, true);
  assert.ok(userIdentityState.address);
});

test('restoreIdentity: derives, publishes, records provenance and the secret', async () => {
  await clearViaRemove();
  const status = await restoreIdentity(GOOD_12);
  assert.equal(status.established, true);
  assert.equal(status.source, 'restored');
  assert.match(status.address, ADDRESS_RE);
  assert.equal(status.preview, false);
  assert.equal(getEthAddress(), status.address);
  assert.equal(userIdentityState.source, 'restored');
  assert.equal(getIdentitySecretBytes().length, 32);
});

test('restoreIdentity: an invalid phrase throws and persists nothing', async () => {
  await clearViaRemove();
  await assert.rejects(
    () => restoreIdentity('one two three four'),
    (err) => err instanceof InvalidMnemonicError && err.code === MNEMONIC_ERRORS.WORD_COUNT,
  );
  assert.equal(memory.getItem(STORAGE_KEYS.USER_IDENTITY), null);
  assert.equal(getUserIdentity().established, false);
});

test('createIdentity with an explicit phrase is rejected when invalid', async () => {
  await clearViaRemove();
  await assert.rejects(
    () => createIdentity({ mnemonic: `${'abandon '.repeat(11)}art`.trim() }),
    (err) => err instanceof InvalidMnemonicError && err.code === MNEMONIC_ERRORS.CHECKSUM,
  );
  assert.equal(getUserIdentity().established, false);
});

test('round trip: restore of the created phrase reproduces its address', async () => {
  await clearViaRemove();
  const { inputMnemonic } = await createIdentity();
  const firstAddress = getEthAddress();
  await clearViaRemove();
  const status = await restoreIdentity(inputMnemonic);
  assert.equal(status.address, firstAddress, 'same phrase → same account on any device');
});

test('wipeIdentity clears the record, the stored secret and the published view', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  assert.equal(getUserIdentity().established, true);
  assert.ok(getIdentitySecretBytes(), 'secret present before wipe');
  await wipeIdentity();
  assert.equal(memory.getItem(STORAGE_KEYS.USER_IDENTITY), null);
  assert.equal(getIdentitySecretBytes(), null);
  const status = getUserIdentity();
  assert.equal(status.established, false);
  assert.equal(status.address, null);
  assert.equal(userIdentityState.established, false);
  assert.equal(userIdentityState.address, null);
  assert.equal(getEthAddress(), null);
});

// ── Reload path (wasm node) ────────────────────────────────────────────────

/** A fake wasm module + node faithful enough to run `_spawnRealNode` joined. */
function makeJoinedBootWasm(opts = {}) {
  const applied = [];
  const registered = [];
  const node = {
    endpoint_id: () => 'boot-node',
    import_state() {},
    import_ledger_state() {},
    export_state: () => new Uint8Array([1]),
    export_ledger_state: () => new Uint8Array([2]),
    set_user_identity_from_secret(secret) {
      applied.push(Uint8Array.from(secret));
    },
    user_eth_address: () => '0x' + 'ab'.repeat(20),
    async register_eth_address() {
      registered.push(true);
      return opts.registerReply ?? 'accepted';
    },
    ledger_status: () => ({
      address: '0.3.1',
      parent: 'parent-node',
      balance: null,
      height: null,
      pinned_ledger: null,
      state_root: null,
      pending: 0,
      activity: 0,
      free() {},
    }),
    pending_orders: () => [],
    pinned_leaf_keys: () => [],
    join_status: () => ({
      state: 'joined',
      parent: 'parent-node',
      slot: 1,
      address: '0.3.1',
      reason: null,
      reject_code: null,
      free() {},
    }),
    pending_join_outbound: () => null,
    local_snapshot: () => ({ parent: 'parent-node', free() {} }),
    ledger_activity: () => [],
    settlement_records: () => [],
    async request_balance() {
      return 'delivered';
    },
    free() {},
  };
  const wasm = {
    ClientNode: { spawn_control: async () => node },
    generate_secret_key: () => new Uint8Array(32),
  };
  return { wasm, node, applied, registered };
}

test('reload: the stored derived secret is pushed to the node and the anchor registers', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const expectedSecret = getIdentitySecretBytes();

  const { wasm, applied, registered } = makeJoinedBootWasm();
  // The boot seam starts in mock mode (like `initApi`); the boot itself must
  // flip the module live. If the flip happens too late (after the post-spawn
  // syncs), the joined-identity registration below is silently skipped.
  assert.equal(isMockMode(), true, 'boot seam starts in mock mode');
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    assert.equal(isMockMode(), false, 'a successful boot reflects live mode');

    // `_maybeRegisterEthAddress` is fire-and-forget; let it settle.
    await new Promise((resolve) => setTimeout(resolve, 0));

    assert.deepEqual(applied, [Uint8Array.from(expectedSecret)], 'secret restored on reload');
    assert.equal(registered.length, 1, 'register_eth_address called once for the joined identity');
    const reg = getEthRegistrationStatus();
    assert.equal(reg.status, 'accepted');
    assert.equal(reg.trigger, 'boot');
  } finally {
    stop();
  }
});

test('reload: a rejected registration is recorded, not thrown', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);

  const { wasm } = makeJoinedBootWasm({ registerReply: 'rejected:write_once' });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    await new Promise((resolve) => setTimeout(resolve, 0));
    const reg = getEthRegistrationStatus();
    assert.equal(reg.status, 'rejected:write_once');
    assert.equal(reg.trigger, 'boot');
  } finally {
    stop();
  }
});

test('boot: a failed boot leaves mock mode and never registers the anchor', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);

  // The node is created, but the boot throws before it is assigned/live, so the
  // live-mode flip must not have happened. `register_eth_address` is a spy that
  // stays empty because no post-spawn sync may run on a failed boot.
  const registered = [];
  const node = {
    endpoint_id() {
      throw new Error('boot failed after node creation');
    },
    async register_eth_address() {
      registered.push(true);
      return 'accepted';
    },
  };
  const wasm = {
    ClientNode: { spawn_control: async () => node },
    generate_secret_key: () => new Uint8Array(32),
  };

  await assert.rejects(
    () => __bootRealNodeForTest(wasm),
    /boot failed after node creation/,
    'the failed boot rejects',
  );
  assert.equal(isMockMode(), true, 'a failed boot stays in mock mode (never mislabeled live)');
  assert.equal(registered.length, 0, 'no ETH anchor registration on a failed boot');
});

// ── Passkey (still deferred) ───────────────────────────────────────────────

test('passkey: unavailable contexts hide it, enroll/unlock stay honest', async () => {
  // Established identity from the previous test.
  assert.equal(await hasPasskey(), false);
  await assert.rejects(() => enrollPasskey(), (err) => err instanceof PasskeyUnavailableError);
  await assert.rejects(() => unlockWithPasskey(), (err) => err instanceof PasskeyUnavailableError);

  // A secure context with WebAuthn flips feature detection on…
  const previousWindow = globalThis.window;
  globalThis.window = {
    ...previousWindow,
    isSecureContext: true,
    PublicKeyCredential: function PublicKeyCredential() {},
  };
  try {
    assert.equal(isPasskeyAvailable(), true);

    // …but the PRF wrap backend is not connected, so enroll says so plainly
    // and nothing is recorded as enrolled.
    await assert.rejects(
      () => enrollPasskey(),
      (err) => err instanceof IdentityBackendUnavailableError && /crypto update/.test(err.message),
    );
    assert.equal(getUserIdentity().passkeyEnrolled, false);

    // Unlock before enrollment: clear "not set up" state, not a fake success.
    await assert.rejects(
      () => unlockWithPasskey(),
      (err) => err instanceof PasskeyUnavailableError && /No passkey is set up/.test(err.message),
    );

    // Removal is a plain local state change and never fails.
    const afterRemove = await removePasskey();
    assert.equal(afterRemove.passkeyEnrolled, false);
    assert.equal(afterRemove.established, true);
  } finally {
    globalThis.window = previousWindow;
  }
  assert.equal(isPasskeyAvailable(), false);
});

test('hasPasskey stays false on insecure contexts even if a record claims enrollment', async () => {
  // Force the record's flag on directly through the stored JSON.
  const raw = JSON.parse(memory.getItem(STORAGE_KEYS.USER_IDENTITY));
  raw.passkeyEnrolled = true;
  memory.setItem(STORAGE_KEYS.USER_IDENTITY, JSON.stringify(raw));
  assert.equal(await hasPasskey(), false, 'feature detection gates the flag');
  // Clean the flag back off for later tests.
  raw.passkeyEnrolled = false;
  memory.setItem(STORAGE_KEYS.USER_IDENTITY, JSON.stringify(raw));
});

/** Remove the stored record the way a fresh device would look. */
async function clearViaRemove() {
  memory.removeItem(STORAGE_KEYS.USER_IDENTITY);
  refreshUserIdentity();
  assert.equal(getUserIdentity().established, false);
}
