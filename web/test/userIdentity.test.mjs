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
  getPasskeyStatus,
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
  rotateUserEthIdentity,
  __bootRealNodeForTest,
  getEthRegistrationStatus,
  isMockMode,
  InvalidMnemonicError,
  PasskeyUnavailableError,
  PasskeyUnsupportedError,
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
  __resetPasskeyStateForTest,
} = await import('../src/lib/userIdentity.js');

// Inject the mock before any derivation-dependent test runs.
setIdentityBackend(mockBackend);

const GOOD_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

test('the real crypto backend and the WebAuthn PRF key-wrap backend are connected', () => {
  assert.equal(USER_IDENTITY_BACKEND_READY, true);
  assert.equal(PASSKEY_BACKEND_READY, true);
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
  const rotated = [];
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
    async rotate_eth_address(secret) {
      rotated.push(Uint8Array.from(secret));
      if (opts.rotateThrows) throw new Error(opts.rotateThrows);
      return opts.rotateReply ?? 'accepted';
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
  return { wasm, node, applied, registered, rotated };
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

// ── ETH anchor rotation (control variant 24, incumbent-authorized) ─────────

/** A second valid BIP-39 vector, distinct from GOOD_12 (official test seed). */
const NEW_12 =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';

test('rotateUserEthIdentity: the incumbent authorizes the move and the new secret is persisted', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const incumbentAddress = getEthAddress();
  const incumbentSecretHex = hex(getIdentitySecretBytes());

  const expectedNewAddress = await mockBackend.deriveAddress(NEW_12, '');
  const expectedNewSecret = await mockBackend.secretBytes(NEW_12, '');

  const { wasm, rotated } = makeJoinedBootWasm();
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    await new Promise((resolve) => setTimeout(resolve, 0));

    const result = await rotateUserEthIdentity(NEW_12);
    assert.equal(result.status, 'accepted');
    assert.equal(result.previousAddress, incumbentAddress);
    assert.equal(result.address, expectedNewAddress);

    // The wasm node is handed the NEW derived secret; it builds the
    // incumbent-authorized rotation proof internally.
    assert.equal(rotated.length, 1, 'rotate_eth_address called once');
    assert.deepEqual(rotated[0], Uint8Array.from(expectedNewSecret));

    // Persisted: the new address + secret replace the incumbent.
    assert.equal(getEthAddress(), expectedNewAddress);
    assert.equal(hex(getIdentitySecretBytes()), hex(expectedNewSecret));
    assert.notEqual(getEthAddress(), incumbentAddress);
    assert.notEqual(hex(getIdentitySecretBytes()), incumbentSecretHex);
    assert.equal(userIdentityState.address, expectedNewAddress, 'reactive store republished');
  } finally {
    stop();
  }
});

test('rotateUserEthIdentity: a rotation the client reconciled as already-applied persists the new secret', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const incumbentAddress = getEthAddress();

  const expectedNewAddress = await mockBackend.deriveAddress(NEW_12, '');
  const expectedNewSecret = await mockBackend.secretBytes(NEW_12, '');

  // The wasm client owns the idempotent commit: it resends the identical frame
  // after a lost reply and treats a `Replay` as already-applied, reporting that
  // reconciled outcome as the ordinary `accepted` bucket. The web layer must
  // persist exactly as on a first-attempt acceptance — this is what stops a
  // lost reply from leaving the device on the incumbent while the parent anchor
  // moved.
  const { wasm } = makeJoinedBootWasm({ rotateReply: 'accepted' });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    await new Promise((resolve) => setTimeout(resolve, 0));

    const result = await rotateUserEthIdentity(NEW_12);
    assert.equal(result.status, 'accepted');
    assert.equal(result.previousAddress, incumbentAddress);
    assert.equal(result.address, expectedNewAddress);
    assert.equal(getEthAddress(), expectedNewAddress, 'reconciled acceptance persists the new address');
    assert.equal(
      hex(getIdentitySecretBytes()),
      hex(expectedNewSecret),
      'reconciled acceptance persists the new secret',
    );
    assert.equal(userIdentityState.address, expectedNewAddress, 'reactive store republished');
  } finally {
    stop();
  }
});

test('rotateUserEthIdentity: a parent rejection leaves the incumbent identity unchanged', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const incumbentAddress = getEthAddress();
  const incumbentSecretHex = hex(getIdentitySecretBytes());

  const { wasm, rotated } = makeJoinedBootWasm({ rotateReply: 'rejected:unauthorized' });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    await new Promise((resolve) => setTimeout(resolve, 0));

    const result = await rotateUserEthIdentity(NEW_12);
    assert.equal(result.status, 'rejected:unauthorized');
    assert.equal(result.address, incumbentAddress);
    assert.equal(rotated.length, 1, 'the node was asked to rotate');
    assert.equal(getEthAddress(), incumbentAddress, 'incumbent address kept');
    assert.equal(hex(getIdentitySecretBytes()), incumbentSecretHex, 'incumbent secret kept');
  } finally {
    stop();
  }
});

test('rotateUserEthIdentity: a transport failure leaves the incumbent identity unchanged', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const incumbentAddress = getEthAddress();
  const incumbentSecretHex = hex(getIdentitySecretBytes());

  const { wasm } = makeJoinedBootWasm({ rotateThrows: 'rotate eth address: parent unreachable' });
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    await new Promise((resolve) => setTimeout(resolve, 0));

    await assert.rejects(
      () => rotateUserEthIdentity(NEW_12),
      /parent unreachable/,
      'the transport error propagates',
    );
    assert.equal(getEthAddress(), incumbentAddress, 'incumbent address kept');
    assert.equal(hex(getIdentitySecretBytes()), incumbentSecretHex, 'incumbent secret kept');
  } finally {
    stop();
  }
});

test('rotateUserEthIdentity: an invalid new phrase sends nothing and persists nothing', async () => {
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const incumbentAddress = getEthAddress();
  const incumbentSecretHex = hex(getIdentitySecretBytes());

  const { wasm, rotated } = makeJoinedBootWasm();
  const { stop } = await __bootRealNodeForTest(wasm);
  try {
    await new Promise((resolve) => setTimeout(resolve, 0));

    await assert.rejects(
      () => rotateUserEthIdentity('not a phrase'),
      (err) => err instanceof InvalidMnemonicError,
      'the invalid phrase is rejected',
    );
    assert.equal(rotated.length, 0, 'no rotation request was sent');
    assert.equal(getEthAddress(), incumbentAddress);
    assert.equal(hex(getIdentitySecretBytes()), incumbentSecretHex);
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

// ── Passkey lock (WebAuthn PRF key-wrap) ───────────────────────────────────

/** A window mock at a specific origin (all four fields the predicate reads). */
function windowAtOrigin(protocol, hostname, isSecureContext) {
  return {
    localStorage: memory,
    isSecureContext,
    PublicKeyCredential: function PublicKeyCredential() {},
    location: { protocol, hostname },
  };
}

test('isPasskeyAvailable gates on the origin, not isSecureContext (file:// stays hidden)', () => {
  const previousWindow = globalThis.window;
  try {
    // `file://` IS a trustworthy secure context that exposes WebAuthn, yet
    // WebAuthn has no valid RP ID for a null origin: the affordance must stay
    // hidden so the mnemonic is the sole unlock path (spec §1.1/§4).
    globalThis.window = windowAtOrigin('file:', '', true);
    assert.equal(isPasskeyAvailable(), false, 'file:// hidden despite isSecureContext');

    // Plain http on a non-loopback host: neither secure nor a valid RP ID.
    globalThis.window = windowAtOrigin('http:', 'example.com', false);
    assert.equal(isPasskeyAvailable(), false, 'plain http://example.com hidden');

    // https anywhere is a valid RP ID.
    globalThis.window = windowAtOrigin('https:', 'example.com', true);
    assert.equal(isPasskeyAvailable(), true, 'https://example.com allowed');

    // http on loopback (Vite dev server) is potentially trustworthy.
    globalThis.window = windowAtOrigin('http:', 'localhost', true);
    assert.equal(isPasskeyAvailable(), true, 'http://localhost:5173 allowed');
    globalThis.window = windowAtOrigin('http:', '127.0.0.1', true);
    assert.equal(isPasskeyAvailable(), true, 'http://127.0.0.1 allowed');
    globalThis.window = windowAtOrigin('http:', '[::1]', true);
    assert.equal(isPasskeyAvailable(), true, 'http://[::1] allowed');

    // Missing location / missing WebAuthn API both stay hidden.
    globalThis.window = {
      localStorage: memory,
      PublicKeyCredential: function PublicKeyCredential() {},
    };
    assert.equal(isPasskeyAvailable(), false, 'no location → hidden');
    globalThis.window = {
      localStorage: memory,
      location: { protocol: 'https:', hostname: 'example.com' },
    };
    assert.equal(isPasskeyAvailable(), false, 'no PublicKeyCredential → hidden');
  } finally {
    globalThis.window = previousWindow;
  }
  assert.equal(isPasskeyAvailable(), false, 'default mock window stays hidden');
});

/**
 * Install a WebAuthn mock: a `PublicKeyCredential` on `window` and a
 * `navigator.credentials` container. The PRF result is deterministic so the
 * wrapped secret can be unwrapped in a later assertion.
 */
function installPasskeyMock({
  prfOutput = new Uint8Array(32).fill(7),
  prfEnabled = true,
  prfResultsAtCreate = true,
  getReturnsWrongPrf = false,
  getThrows = null,
  clientCapabilitiesPrf = undefined,
} = {}) {
  const state = { createCalls: 0, getCalls: 0, createId: null, lastAllowCredentials: null };
  let credentialCounter = 0;

  const PublicKeyCredential = function PublicKeyCredential() {};
  if (clientCapabilitiesPrf !== undefined) {
    PublicKeyCredential.getClientCapabilities = async () => ({ prf: clientCapabilitiesPrf });
  }

  const credentials = {
    async create() {
      credentialCounter += 1;
      state.createCalls += 1;
      const rawId = new Uint8Array(16).fill(credentialCounter);
      state.createId = rawId;
      return {
        type: 'public-key',
        id: `credential-${credentialCounter}`,
        rawId: rawId.buffer,
        getClientExtensionResults: () => ({
          prf: prfResultsAtCreate
            ? { enabled: prfEnabled, results: prfEnabled ? { first: prfOutput } : undefined }
            : { enabled: prfEnabled },
        }),
      };
    },
    async get({ publicKey }) {
      state.getCalls += 1;
      state.lastAllowCredentials = publicKey.allowCredentials;
      if (getThrows) throw new Error(getThrows);
      return {
        type: 'public-key',
        id: 'credential-1',
        rawId: (state.createId ?? new Uint8Array(16)).buffer,
        getClientExtensionResults: () => ({
          prf: prfEnabled
            ? {
                enabled: true,
                results: {
                  first: getReturnsWrongPrf ? new Uint8Array(32).fill(200) : prfOutput,
                },
              }
            : { enabled: false },
        }),
      };
    },
  };

  return { state, PublicKeyCredential, credentials };
}

/** Point the global window/navigator at a secure origin with a WebAuthn mock. */
function useSecurePasskeyContext(mock) {
  const previousWindow = globalThis.window;
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  globalThis.window = {
    localStorage: memory,
    isSecureContext: true,
    PublicKeyCredential: mock.PublicKeyCredential,
    location: { protocol: 'https:', hostname: 'example.com' },
  };
  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials: mock.credentials },
    configurable: true,
    writable: true,
  });
  return () => {
    globalThis.window = previousWindow;
    if (previousNavigator) Object.defineProperty(globalThis, 'navigator', previousNavigator);
    else delete globalThis.navigator;
  };
}

test('passkey: unavailable contexts hide it, enroll/unlock stay honest', async () => {
  __resetPasskeyStateForTest();
  assert.equal(await hasPasskey(), false);
  await assert.rejects(() => enrollPasskey(), (err) => err instanceof PasskeyUnavailableError);
  await assert.rejects(() => unlockWithPasskey(), (err) => err instanceof PasskeyUnavailableError);

  // A secure origin with WebAuthn flips feature detection on; PRF stays
  // undetermined until the first credential is created.
  const previousWindow = globalThis.window;
  globalThis.window = windowAtOrigin('https:', 'example.com', true);
  try {
    assert.equal(isPasskeyAvailable(), true);
    const status = getPasskeyStatus();
    assert.equal(status.available, true);
    assert.equal(status.prfSupported, null, 'PRF undetermined before first use');
    assert.equal(status.enrolled, false);
    assert.equal(status.locked, false);
  } finally {
    globalThis.window = previousWindow;
  }
  assert.equal(isPasskeyAvailable(), false);
});

test('passkey lock: enroll locks, unlock installs, remove goes seamless', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const plaintext = getIdentitySecretBytes();
  assert.ok(plaintext, 'plaintext secret present before enrollment');

  const mock = installPasskeyMock();
  const restoreCtx = useSecurePasskeyContext(mock);
  try {
    assert.deepEqual(getPasskeyStatus(), {
      available: true,
      prfSupported: null,
      enrolled: false,
      locked: false,
    });

    const enrolled = await enrollPasskey();
    assert.equal(enrolled.established, true);
    assert.equal(enrolled.passkeyEnrolled, true);

    // Enroll locks on: plaintext gone, wrap persisted.
    let status = getPasskeyStatus();
    assert.deepEqual(status, { available: true, prfSupported: true, enrolled: true, locked: true });
    assert.equal(getIdentitySecretBytes(), null, 'plaintext secret is gone while locked');
    const raw = memory.getItem(STORAGE_KEYS.USER_IDENTITY);
    assert.equal(raw.includes(hex(plaintext)), false, 'plaintext secret absent from storage');
    const record = JSON.parse(raw);
    assert.equal(record.v, USER_IDENTITY_VERSION);
    assert.equal(record.secret, null);
    assert.ok(record.passkey, 'wrap stored');
    assert.equal(typeof record.passkey.credentialId, 'string');
    assert.equal(typeof record.passkey.salt, 'string');
    assert.equal(typeof record.passkey.iv, 'string');
    assert.equal(typeof record.passkey.ct, 'string');
    assert.equal('passkeyEnrolled' in record, false, 'legacy boolean dropped');

    // Unlock installs the exact secret for the session; the wrap is retained
    // (a reload re-locks) and the plaintext is not persisted again.
    const unlocked = await unlockWithPasskey();
    assert.equal(unlocked.passkeyEnrolled, true);
    status = getPasskeyStatus();
    assert.deepEqual(status, { available: true, prfSupported: true, enrolled: true, locked: false });
    assert.deepEqual(getIdentitySecretBytes(), plaintext, 'unlock restores the exact secret');
    const stillWrapped = JSON.parse(memory.getItem(STORAGE_KEYS.USER_IDENTITY));
    assert.equal(stillWrapped.secret, null, 'unlock does not persist the plaintext again');
    assert.ok(stillWrapped.passkey, 'wrap retained across sessions');

    // Remove goes seamless: plaintext persisted, wrap cleared.
    const removed = await removePasskey();
    assert.equal(removed.passkeyEnrolled, false);
    status = getPasskeyStatus();
    assert.deepEqual(status, { available: true, prfSupported: true, enrolled: false, locked: false });
    const finalRecord = JSON.parse(memory.getItem(STORAGE_KEYS.USER_IDENTITY));
    assert.equal(finalRecord.passkey, null);
    assert.equal(finalRecord.secret, hex(plaintext));
  } finally {
    restoreCtx();
    __resetPasskeyStateForTest();
  }
});

test('passkey lock: a reload re-locks, and a fresh unlock unwraps from storage', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const plaintext = getIdentitySecretBytes();

  const mock = installPasskeyMock();
  const firstCtx = useSecurePasskeyContext(mock);
  try {
    await enrollPasskey();
  } finally {
    firstCtx();
  }

  // Drop the in-memory session (as a page reload would) but keep the wrap.
  __resetPasskeyStateForTest();
  assert.equal(getIdentitySecretBytes(), null, 'locked again after a reload');
  assert.equal(getPasskeyStatus().locked, true);

  const secondCtx = useSecurePasskeyContext(mock);
  try {
    await unlockWithPasskey();
    assert.deepEqual(getIdentitySecretBytes(), plaintext, 'reload unlock repopulates the session');
    assert.equal(getPasskeyStatus().locked, false);
  } finally {
    secondCtx();
    __resetPasskeyStateForTest();
  }
});

test('passkey lock: a wrong PRF output fails the unwrap and changes nothing', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);

  const mock = installPasskeyMock({ getReturnsWrongPrf: true });
  const restoreCtx = useSecurePasskeyContext(mock);
  try {
    await enrollPasskey();
    const before = memory.getItem(STORAGE_KEYS.USER_IDENTITY);
    assert.equal(getPasskeyStatus().locked, true);

    await assert.rejects(() => unlockWithPasskey(), /did not match/);
    assert.equal(getPasskeyStatus().locked, true, 'still locked');
    assert.equal(getIdentitySecretBytes(), null);
    assert.equal(memory.getItem(STORAGE_KEYS.USER_IDENTITY), before, 'record untouched');
  } finally {
    restoreCtx();
    __resetPasskeyStateForTest();
  }
});

test('passkey lock: a rejected assertion (user cancel) is a no-op', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);

  const mock = installPasskeyMock({ getThrows: 'user cancelled' });
  const restoreCtx = useSecurePasskeyContext(mock);
  try {
    await enrollPasskey();
    await assert.rejects(() => unlockWithPasskey(), /user cancelled/);
    assert.equal(getPasskeyStatus().locked, true);
    assert.equal(getIdentitySecretBytes(), null);
  } finally {
    restoreCtx();
    __resetPasskeyStateForTest();
  }
});

test('passkey lock: unsupported PRF reports prfSupported:false and refuses enrollment', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const plaintext = getIdentitySecretBytes();

  const mock = installPasskeyMock({ prfEnabled: false });
  const restoreCtx = useSecurePasskeyContext(mock);
  try {
    await assert.rejects(() => enrollPasskey(), PasskeyUnsupportedError);
    const status = getPasskeyStatus();
    assert.equal(status.prfSupported, false);
    assert.equal(status.enrolled, false);
    assert.equal(status.locked, false);
    // No weaker gate-only lock: the plaintext secret is untouched.
    assert.deepEqual(getIdentitySecretBytes(), plaintext);
    const record = JSON.parse(memory.getItem(STORAGE_KEYS.USER_IDENTITY));
    assert.equal(record.passkey, null);
    assert.equal(record.secret, hex(plaintext));
  } finally {
    restoreCtx();
    __resetPasskeyStateForTest();
  }
});

test('passkey lock: getClientCapabilities prf:false short-circuits enrollment', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const plaintext = getIdentitySecretBytes();

  const mock = installPasskeyMock({ clientCapabilitiesPrf: false });
  const restoreCtx = useSecurePasskeyContext(mock);
  try {
    await assert.rejects(() => enrollPasskey(), PasskeyUnsupportedError);
    assert.equal(getPasskeyStatus().prfSupported, false);
    assert.equal(mock.state.createCalls, 0, 'no credential created when PRF is known unsupported');
    assert.deepEqual(getIdentitySecretBytes(), plaintext);
  } finally {
    restoreCtx();
    __resetPasskeyStateForTest();
  }
});

test('passkey lock: a locked boot never installs the secret on the node', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);

  const mock = installPasskeyMock();
  const restoreCtx = useSecurePasskeyContext(mock);
  try {
    await enrollPasskey();
    assert.equal(getPasskeyStatus().locked, true);

    // Boot the fake node while locked: `getIdentitySecretBytes()` is null, so
    // the stored secret must not reach the node.
    const { wasm, applied } = makeJoinedBootWasm();
    const boot = await __bootRealNodeForTest(wasm);
    try {
      await new Promise((resolve) => setTimeout(resolve, 0));
      assert.equal(applied.length, 0, 'locked boot does not install the secret');
    } finally {
      boot.stop();
    }
  } finally {
    restoreCtx();
    __resetPasskeyStateForTest();
  }
});

test('passkey lock: unlocking re-applies the secret to a live node', async () => {
  __resetPasskeyStateForTest();
  await clearViaRemove();
  await restoreIdentity(GOOD_12);
  const plaintext = getIdentitySecretBytes();

  const mock = installPasskeyMock();
  const restoreCtx = useSecurePasskeyContext(mock);
  try {
    await enrollPasskey();

    const { wasm, applied } = makeJoinedBootWasm();
    const boot = await __bootRealNodeForTest(wasm);
    try {
      await new Promise((resolve) => setTimeout(resolve, 0));
      assert.equal(applied.length, 0, 'locked boot installs nothing');

      await unlockWithPasskey();
      assert.deepEqual(applied[applied.length - 1], plaintext, 'unlock re-applies the secret');
    } finally {
      boot.stop();
    }
  } finally {
    restoreCtx();
    __resetPasskeyStateForTest();
  }
});

test('hasPasskey stays false on insecure contexts even if a record claims enrollment', async () => {
  // Force a wrap onto the record directly through the stored JSON.
  const raw = JSON.parse(memory.getItem(STORAGE_KEYS.USER_IDENTITY));
  raw.passkey = { credentialId: 'x', salt: 's', iv: 'i', ct: 'c' };
  memory.setItem(STORAGE_KEYS.USER_IDENTITY, JSON.stringify(raw));
  assert.equal(getUserIdentity().passkeyEnrolled, true, 'record reports enrollment');
  assert.equal(await hasPasskey(), false, 'feature detection gates the flag');
  // Clean the wrap back off for later tests.
  raw.passkey = null;
  memory.setItem(STORAGE_KEYS.USER_IDENTITY, JSON.stringify(raw));
});

/** Remove the stored record the way a fresh device would look. */
async function clearViaRemove() {
  memory.removeItem(STORAGE_KEYS.USER_IDENTITY);
  refreshUserIdentity();
  assert.equal(getUserIdentity().established, false);
}
