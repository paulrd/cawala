/**
 * Cawala — portable identity bundle (increment 2, client-side only).
 *
 * A logged-in user leaf owns a 32-byte Ed25519 seed (stored by `api.js` as hex
 * in `localStorage['cawala.identity.v1']`) AND an R3 user identity: a
 * secp256k1 key derived from a BIP-39 mnemonic (EIP-55 address, stored — never
 * the mnemonic — as `localStorage['cawala.user-identity.v1']`). This module
 * wraps the transport seed, the optional derived secp256k1 secret + address,
 * and the optional opaque postcard state/ledger blobs in a
 * passphrase-encrypted, JSON-serializable bundle that can be moved to another
 * device.
 *
 * Crypto: WebCrypto only (`globalThis.crypto.subtle`), works in browsers and in
 * Node 24. PBKDF2-SHA-256 derives a 256-bit AES-GCM key; a fresh 16-byte salt
 * and 12-byte IV are generated per export. The bundle's cleartext `nodeId` is
 * bound into the ciphertext via AES-GCM additional authenticated data (AAD),
 * so tampering with it fails decryption. v2 keeps the exact v1 KDF/AEAD/AAD;
 * it only widens the encrypted payload.
 *
 * Versioning:
 *   - v1 (legacy) encrypted `{ seedHex, stateB64, ledgerB64 }` only — no R3
 *     ETH identity. Still decryptable; importing one restores the transport
 *     seed + blobs and leaves no ETH identity.
 *   - v2 adds the derived secp256k1 `ethSecretHex` + denormalized `ethAddress`
 *     to the encrypted payload so import restores the same ETH identity. The
 *     fields are omitted entirely when no R3 identity exists, which makes the
 *     v2-without-identity payload byte-identical to the v1 payload.
 *
 * Pure ESM, no DOM, no dependencies.
 */

export const IDENTITY_BUNDLE_VERSION = 2;
/** The legacy v1 bundle shape (transport seed + blobs only), still accepted. */
export const LEGACY_IDENTITY_BUNDLE_VERSION = 1;
export const PBKDF2_ITERATIONS = 600_000;

const KDF_NAME = 'PBKDF2-SHA-256';
const AEAD_NAME = 'AES-256-GCM';
const AAD_PREFIX = 'cawala.identity.bundle.v1:';
const HEX64 = /^[0-9a-f]{64}$/i;
const ETH_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
/** Bundle versions this build can decrypt. */
const SUPPORTED_BUNDLE_VERSIONS = [LEGACY_IDENTITY_BUNDLE_VERSION, IDENTITY_BUNDLE_VERSION];

// ── Public API ────────────────────────────────────────────────

/**
 * Encrypt an identity bundle (always the current v2 shape).
 *
 * @param {object} input
 * @param {string} input.seedHex 32-byte Ed25519 seed as 64 hex chars.
 * @param {string|null} [input.ethSecretHex] Derived secp256k1 secret (64 hex),
 *   or null when this device has no R3 user identity.
 * @param {string|null} [input.ethAddress] EIP-55 checksummed address for
 *   display (case preserved), or null when there is no R3 identity.
 * @param {string|null} [input.stateB64] Opaque exported state blob (base64).
 * @param {string|null} [input.ledgerB64] Opaque exported ledger blob (base64).
 * @param {string} input.nodeId Endpoint id / operator key as 64 hex chars.
 * @param {string} input.passphrase Non-empty passphrase.
 * @returns {Promise<{ v: number, nodeId: string, kdf: object, aead: object, ct: string }>}
 */
export async function encryptIdentityBundle({
  seedHex,
  ethSecretHex = null,
  ethAddress = null,
  stateB64 = null,
  ledgerB64 = null,
  nodeId,
  passphrase,
}) {
  const normalizedSeed = _requireHex64(seedHex, 'seedHex must be exactly 64 hex characters');
  const normalizedNode = _requireHex64(nodeId, 'nodeId must be exactly 64 hex characters');
  const eth = _normalizeEthIdentity(ethSecretHex, ethAddress);
  _requirePassphrase(passphrase);

  const salt = _randomBytes(16);
  const iv = _randomBytes(12);
  const key = await _deriveKey(passphrase, salt, PBKDF2_ITERATIONS);

  const payload = {
    seedHex: normalizedSeed,
    stateB64: typeof stateB64 === 'string' ? stateB64 : null,
    ledgerB64: typeof ledgerB64 === 'string' ? ledgerB64 : null,
  };
  // Omit the ETH fields entirely when absent: this keeps the no-identity
  // payload identical to the legacy v1 shape.
  if (eth.secretHex != null) {
    payload.ethSecretHex = eth.secretHex;
    payload.ethAddress = eth.address;
  }

  const plaintext = _utf8Encode(JSON.stringify(payload));

  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: _aad(normalizedNode) },
    key,
    plaintext,
  );

  return {
    v: IDENTITY_BUNDLE_VERSION,
    nodeId: normalizedNode,
    kdf: {
      name: KDF_NAME,
      iterations: PBKDF2_ITERATIONS,
      salt: _bytesToBase64(salt),
    },
    aead: {
      name: AEAD_NAME,
      iv: _bytesToBase64(iv),
    },
    ct: _bytesToBase64(new Uint8Array(ciphertext)),
  };
}

/**
 * Decrypt an identity bundle (v1 or v2).
 *
 * @param {object} bundle
 * @param {string} passphrase
 * @returns {Promise<{ version: number, nodeId: string, seedHex: string, ethSecretHex: string|null, ethAddress: string|null, stateB64: string|null, ledgerB64: string|null }>}
 */
export async function decryptIdentityBundle(bundle, passphrase) {
  _requirePassphrase(passphrase);
  const meta = inspectIdentityBundle(bundle);

  const salt = _base64ToBytes(bundle.kdf.salt);
  const iv = _base64ToBytes(bundle.aead.iv);
  const key = await _deriveKey(passphrase, salt, bundle.kdf.iterations);

  let plaintext;
  try {
    plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: _aad(meta.nodeId) },
      key,
      _base64ToBytes(bundle.ct),
    );
  } catch {
    throw new Error('Incorrect passphrase or corrupted bundle');
  }

  let payload;
  try {
    payload = JSON.parse(_utf8Decode(plaintext));
  } catch {
    throw new Error('Malformed identity bundle');
  }

  const seedHex = payload?.seedHex;
  if (typeof seedHex !== 'string' || !HEX64.test(seedHex)) {
    throw new Error('Malformed identity bundle');
  }
  // A v1 bundle has neither field; a v2 bundle has both or neither.
  const eth = _normalizeEthIdentity(payload?.ethSecretHex, payload?.ethAddress);

  return {
    version: meta.version,
    nodeId: meta.nodeId,
    seedHex: seedHex.toLowerCase(),
    ethSecretHex: eth.secretHex,
    ethAddress: eth.address,
    stateB64: typeof payload.stateB64 === 'string' ? payload.stateB64 : null,
    ledgerB64: typeof payload.ledgerB64 === 'string' ? payload.ledgerB64 : null,
  };
}

/**
 * Cleartext metadata after structural validation only. Never touches the
 * passphrase and never decrypts the ciphertext.
 *
 * @param {object} bundle
 * @returns {{ version: number, nodeId: string, kdf: string, aead: string }}
 */
export function inspectIdentityBundle(bundle) {
  if (bundle === null || typeof bundle !== 'object' || Array.isArray(bundle)) {
    throw new Error('Malformed identity bundle');
  }
  if (bundle.v == null) {
    throw new Error('Malformed identity bundle');
  }
  if (!SUPPORTED_BUNDLE_VERSIONS.includes(bundle.v)) {
    throw new Error('Unsupported identity bundle version');
  }
  if (typeof bundle.nodeId !== 'string' || !HEX64.test(bundle.nodeId)) {
    throw new Error('Malformed identity bundle');
  }

  const kdf = bundle.kdf;
  if (kdf === null || typeof kdf !== 'object' || Array.isArray(kdf)) {
    throw new Error('Malformed identity bundle');
  }
  if (kdf.name !== KDF_NAME || !Number.isInteger(kdf.iterations) || kdf.iterations <= 0) {
    throw new Error('Malformed identity bundle');
  }
  if (typeof kdf.salt !== 'string') {
    throw new Error('Malformed identity bundle');
  }
  let salt;
  try {
    salt = _base64ToBytes(kdf.salt);
  } catch {
    throw new Error('Malformed identity bundle');
  }
  if (salt.length !== 16) {
    throw new Error('Malformed identity bundle');
  }

  const aead = bundle.aead;
  if (aead === null || typeof aead !== 'object' || Array.isArray(aead)) {
    throw new Error('Malformed identity bundle');
  }
  if (aead.name !== AEAD_NAME || typeof aead.iv !== 'string') {
    throw new Error('Malformed identity bundle');
  }
  let iv;
  try {
    iv = _base64ToBytes(aead.iv);
  } catch {
    throw new Error('Malformed identity bundle');
  }
  if (iv.length !== 12) {
    throw new Error('Malformed identity bundle');
  }

  if (typeof bundle.ct !== 'string' || bundle.ct === '') {
    throw new Error('Malformed identity bundle');
  }

  return {
    version: bundle.v,
    nodeId: bundle.nodeId,
    kdf: kdf.name,
    aead: aead.name,
  };
}

/**
 * Parse a serialized bundle, throwing a friendly error on malformed JSON.
 *
 * @param {string} text
 * @returns {object}
 */
export function parseIdentityBundle(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    throw new Error('Malformed identity bundle');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('Malformed identity bundle');
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Malformed identity bundle');
  }
  return parsed;
}

/**
 * Serialize a bundle to a JSON string.
 *
 * @param {object} bundle
 * @returns {string}
 */
export function serializeIdentityBundle(bundle) {
  return JSON.stringify(bundle);
}

// ── Internals ─────────────────────────────────────────────────

/**
 * @param {string} hex
 * @param {string} message
 * @returns {string} lowercase hex
 */
function _requireHex64(hex, message) {
  if (typeof hex !== 'string' || !HEX64.test(hex)) {
    throw new Error(message);
  }
  return hex.toLowerCase();
}

/**
 * Normalize the optional R3 ETH identity carried in the encrypted payload.
 * Both fields must be present together; absence of both yields nulls (a v1
 * bundle, or a v2 bundle exported from a device without an R3 identity).
 * The address case is preserved because EIP-55 checksumming is significant.
 *
 * @param {unknown} secretHex
 * @param {unknown} address
 * @returns {{ secretHex: string|null, address: string|null }}
 * @throws {Error} When only one field is present or a field is malformed.
 */
function _normalizeEthIdentity(secretHex, address) {
  const hasSecret = secretHex != null && secretHex !== '';
  const hasAddress = address != null && address !== '';
  if (!hasSecret && !hasAddress) {
    return { secretHex: null, address: null };
  }
  if (
    !hasSecret ||
    !hasAddress ||
    typeof secretHex !== 'string' ||
    !HEX64.test(secretHex) ||
    typeof address !== 'string' ||
    !ETH_ADDRESS.test(address)
  ) {
    throw new Error('Malformed identity bundle');
  }
  return { secretHex: secretHex.toLowerCase(), address };
}

/**
 * @param {unknown} passphrase
 */
function _requirePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Passphrase is required');
  }
}

/**
 * AAD binds the cleartext endpoint id to the ciphertext.
 * @param {string} nodeId
 * @returns {Uint8Array}
 */
function _aad(nodeId) {
  return _utf8Encode(AAD_PREFIX + nodeId);
}

/**
 * Derive a 256-bit AES-GCM key from a passphrase via PBKDF2-SHA-256.
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @returns {Promise<CryptoKey>}
 */
async function _deriveKey(passphrase, salt, iterations) {
  const material = await globalThis.crypto.subtle.importKey(
    'raw',
    _utf8Encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return globalThis.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * @param {number} length
 * @returns {Uint8Array}
 */
function _randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * @param {string} text
 * @returns {Uint8Array}
 */
function _utf8Encode(text) {
  return new TextEncoder().encode(text);
}

/**
 * @param {ArrayBuffer|Uint8Array} bytes
 * @returns {string}
 */
function _utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}

/**
 * Base64 helpers that work in both browsers and Node, dependency-free.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function _bytesToBase64(bytes) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * @param {string} b64
 * @returns {Uint8Array}
 */
function _base64ToBytes(b64) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}
