import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Portable identity-bundle export/import round-trip (F3).
 *
 * The bundle now carries the R3 user ETH identity (derived secp256k1 secret +
 * EIP-55 address) alongside the transport seed and state/ledger blobs, so
 * importing it on a fresh device/origin restores the same ETH account and the
 * node can sign V4 orders. A legacy v1 bundle (transport-only) still imports,
 * with no ETH identity. The crypto round-trip itself is exercised in
 * `identityBundle.test.mjs`; here we drive the api.js boundary.
 *
 * A separate file gives a clean module instance and its own memory storage.
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
  restoreIdentity,
  exportIdentityBundle,
  importIdentityBundle,
  inspectIdentityBundle,
  getEthAddress,
  wipeIdentity,
  __setClientForTest,
} = await import('../src/lib/api.js');
const { STORAGE_KEYS } = await import('../src/lib/storage.js');
const {
  setIdentityBackend,
  getIdentitySecretBytes,
  getUserIdentity,
} = await import('../src/lib/userIdentity.js');
const {
  encryptIdentityBundle,
  serializeIdentityBundle,
  IDENTITY_BUNDLE_VERSION,
  LEGACY_IDENTITY_BUNDLE_VERSION,
} = await import('../src/lib/identityBundle.js');

setIdentityBackend(mockBackend);

const GOOD_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSPHRASE = 'correct horse battery staple';
const NODE_ID = 'b2'.repeat(32);

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A live-node double sufficient for export (endpoint id + blob exports). */
function makeExportNode() {
  return {
    endpoint_id: () => NODE_ID,
    export_state: () => new Uint8Array([1, 2, 3]),
    export_ledger_state: () => new Uint8Array([4, 5, 6]),
    clear_user_identity() {},
    free() {},
  };
}

test('export→import round-trip restores the same ETH identity and signer secret', async () => {
  memory.clear();
  await restoreIdentity(GOOD_12);
  const expectedAddress = getEthAddress();
  const expectedSecret = getIdentitySecretBytes();
  const expectedTransportSeed = await mockBackend.transportSeed(GOOD_12, '');
  assert.ok(expectedAddress, 'identity established');

  __setClientForTest(makeExportNode());
  const text = await exportIdentityBundle(PASSPHRASE);

  const meta = inspectIdentityBundle(text);
  assert.equal(meta.version, IDENTITY_BUNDLE_VERSION, 'v2 bundle');
  assert.equal(meta.nodeId, NODE_ID);

  // Simulate importing on a fresh device: no ETH identity, no transport seed.
  await wipeIdentity();
  assert.equal(getEthAddress(), null);

  const { nodeId, ethAddress } = await importIdentityBundle(text, PASSPHRASE);

  assert.equal(nodeId, NODE_ID);
  assert.equal(ethAddress, expectedAddress, 'import reports the restored address');
  assert.equal(getEthAddress(), expectedAddress, 'same EIP-55 address restored');

  // The restored secret is exactly what the wasm signer is fed — so V4 orders
  // sign as the same account without the mnemonic.
  const restoredSecret = getIdentitySecretBytes();
  assert.deepEqual(restoredSecret, expectedSecret);
  assert.equal(hex(restoredSecret), hex(await mockBackend.secretBytes(GOOD_12, '')));

  // The transport seed is restored too, under the documented keys.
  assert.equal(memory.getItem(STORAGE_KEYS.IDENTITY), hex(expectedTransportSeed));
  const record = JSON.parse(memory.getItem(STORAGE_KEYS.USER_IDENTITY));
  assert.equal(record.address, expectedAddress);
  assert.equal(record.secret, hex(expectedSecret));

  __setClientForTest(null);
});

test('a legacy v1 bundle imports without an ETH identity', async () => {
  memory.clear();
  // Seed a device with an ETH identity so the import must clear it.
  await restoreIdentity(GOOD_12);
  assert.ok(getEthAddress());

  const legacySeedHex = 'a1'.repeat(32);
  const v2 = await encryptIdentityBundle({
    seedHex: legacySeedHex,
    ethSecretHex: null,
    ethAddress: null,
    nodeId: NODE_ID,
    passphrase: PASSPHRASE,
  });
  // With no ETH identity the payload matches the v1 shape exactly; relabel.
  const legacy = serializeIdentityBundle({ ...v2, v: LEGACY_IDENTITY_BUNDLE_VERSION });

  const { nodeId, ethAddress } = await importIdentityBundle(legacy, PASSPHRASE);

  assert.equal(nodeId, NODE_ID);
  assert.equal(ethAddress, null);
  assert.equal(
    memory.getItem(STORAGE_KEYS.IDENTITY),
    legacySeedHex,
    'transport seed restored',
  );
  assert.equal(getEthAddress(), null, 'no ETH identity after a v1 import');
  assert.equal(getIdentitySecretBytes(), null);
  assert.equal(memory.getItem(STORAGE_KEYS.USER_IDENTITY), null);
  assert.equal(getUserIdentity().established, false);
});

test('a tampered bundle fails authentication on import', async () => {
  memory.clear();
  await restoreIdentity(GOOD_12);
  __setClientForTest(makeExportNode());
  const text = await exportIdentityBundle(PASSPHRASE);
  __setClientForTest(null);

  // Wrong passphrase.
  await assert.rejects(
    () => importIdentityBundle(text, 'not the passphrase'),
    /Incorrect passphrase or corrupted bundle/,
  );

  // Tampered cleartext nodeId (AAD mismatch).
  const tamperedNode = { ...JSON.parse(text), nodeId: 'c3'.repeat(32) };
  await assert.rejects(
    () => importIdentityBundle(JSON.stringify(tamperedNode), PASSPHRASE),
    /Incorrect passphrase or corrupted bundle/,
  );

  // Flipped ciphertext byte (GCM tag).
  const parsed = JSON.parse(text);
  const raw = Buffer.from(parsed.ct, 'base64');
  raw[raw.length - 1] ^= 0xff;
  parsed.ct = raw.toString('base64');
  await assert.rejects(
    () => importIdentityBundle(JSON.stringify(parsed), PASSPHRASE),
    /Incorrect passphrase or corrupted bundle/,
  );
});
