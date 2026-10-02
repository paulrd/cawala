/**
 * Cawala — passphrase wrap for delegated admin (value) seeds.
 *
 * A value-scoped K_admin seed can be stored wrapped instead of as plaintext in
 * localStorage. Crypto: PBKDF2-SHA-256 (600_000 iterations, 16-byte salt)
 * derives an AES-256-GCM key; a fresh 12-byte IV is used per wrap; the node id is
 * bound into the ciphertext as AES-GCM additional authenticated data (AAD), so a
 * wrapped record cannot be moved to another node.
 *
 * The wrapped shape is
 * `{ kdf: { name, iterations, salt }, aead: { name, iv }, ct }` — deliberately
 * without the seed. This is **not** the identity-bundle format; that module and
 * its key are untouched.
 *
 * Honest limits: this adds an interaction gate and protects at-rest dumps and
 * copied browser profiles. It does **not** stop in-session XSS while unlocked
 * (the seed is in JS memory and a copy is in the wasm heap after
 * `set_admin_key`); GC makes zeroization best-effort, a fake prompt can phish the
 * passphrase, and PBKDF2 depends on passphrase strength.
 *
 * Pure ESM, WebCrypto only, dependency-free.
 */

export const ADMIN_SEED_KDF_NAME = 'PBKDF2-SHA-256';
export const ADMIN_SEED_AEAD_NAME = 'AES-256-GCM';
export const ADMIN_SEED_PBKDF2_ITERATIONS = 600_000;
export const ADMIN_SEED_AAD_PREFIX = 'cawala.admin.seed.v1:';

const HEX64 = /^[0-9a-f]{64}$/i;

/**
 * Wrap `seedHex` under `passphrase`, bound to `nodeId`.
 *
 * @param {string} seedHex 32-byte seed as 64 hex chars.
 * @param {string} passphrase
 * @param {string} nodeId 64 hex chars.
 * @returns {Promise<{ kdf: object, aead: object, ct: string }>}
 */
export async function wrapSeed(seedHex, passphrase, nodeId) {
  const seed = _requireHex64(seedHex, 'seedHex must be exactly 64 hex characters');
  const node = _requireHex64(nodeId, 'nodeId must be exactly 64 hex characters');
  _requirePassphrase(passphrase);

  const salt = _randomBytes(16);
  const iv = _randomBytes(12);
  const key = await _deriveKey(passphrase, salt, ADMIN_SEED_PBKDF2_ITERATIONS);

  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: _aad(node) },
    key,
    _utf8Encode(JSON.stringify({ seedHex: seed })),
  );

  return {
    kdf: {
      name: ADMIN_SEED_KDF_NAME,
      iterations: ADMIN_SEED_PBKDF2_ITERATIONS,
      salt: _bytesToBase64(salt),
    },
    aead: {
      name: ADMIN_SEED_AEAD_NAME,
      iv: _bytesToBase64(iv),
    },
    ct: _bytesToBase64(new Uint8Array(ciphertext)),
  };
}

/**
 * Unwrap a wrapped seed, throwing on a wrong passphrase, an AAD/node-id
 * mismatch, or a malformed record.
 *
 * @param {object} wrapped
 * @param {string} passphrase
 * @param {string} nodeId
 * @returns {Promise<string>} lowercase 64-hex seed
 */
export async function unwrapSeed(wrapped, passphrase, nodeId) {
  _requirePassphrase(passphrase);
  const meta = inspectWrappedSeed(wrapped);
  const node = _requireHex64(nodeId, 'nodeId must be exactly 64 hex characters');

  const salt = _base64ToBytes(wrapped.kdf.salt);
  const iv = _base64ToBytes(wrapped.aead.iv);
  const key = await _deriveKey(passphrase, salt, wrapped.kdf.iterations);

  let plaintext;
  try {
    plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: _aad(node) },
      key,
      _base64ToBytes(wrapped.ct),
    );
  } catch {
    throw new Error('Incorrect passphrase or corrupted wrapped key');
  }

  let payload;
  try {
    payload = JSON.parse(_utf8Decode(plaintext));
  } catch {
    throw new Error('Malformed wrapped key');
  }
  const seed = payload?.seedHex;
  if (typeof seed !== 'string' || !HEX64.test(seed)) {
    throw new Error('Malformed wrapped key');
  }
  return seed.toLowerCase();
}

/**
 * Structural validation of a wrapped record (no crypto, no passphrase).
 *
 * @param {unknown} wrapped
 * @returns {{ kdf: string, aead: string, iterations: number }}
 */
export function inspectWrappedSeed(wrapped) {
  if (!isWrappedSeed(wrapped)) {
    throw new Error('Malformed wrapped key');
  }
  return {
    kdf: wrapped.kdf.name,
    aead: wrapped.aead.name,
    iterations: wrapped.kdf.iterations,
  };
}

/**
 * Whether `value` is a structurally valid wrapped record. Never throws.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isWrappedSeed(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const kdf = value.kdf;
  if (kdf === null || typeof kdf !== 'object' || Array.isArray(kdf)) return false;
  if (kdf.name !== ADMIN_SEED_KDF_NAME) return false;
  // Bound the iteration count for this v1 format so a tampered record cannot
  // pin a multi-billion-iteration PBKDF2 (a cheap DoS on unlock).
  if (kdf.iterations !== ADMIN_SEED_PBKDF2_ITERATIONS) return false;
  if (typeof kdf.salt !== 'string') return false;
  try {
    if (_base64ToBytes(kdf.salt).length !== 16) return false;
  } catch {
    return false;
  }
  const aead = value.aead;
  if (aead === null || typeof aead !== 'object' || Array.isArray(aead)) return false;
  if (aead.name !== ADMIN_SEED_AEAD_NAME || typeof aead.iv !== 'string') return false;
  try {
    if (_base64ToBytes(aead.iv).length !== 12) return false;
  } catch {
    return false;
  }
  return typeof value.ct === 'string' && value.ct !== '';
}

// ── Internals ─────────────────────────────────────────────────

function _requireHex64(hex, message) {
  if (typeof hex !== 'string' || !HEX64.test(hex)) throw new Error(message);
  return hex.toLowerCase();
}

function _requirePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('Passphrase is required');
  }
}

function _aad(nodeId) {
  return _utf8Encode(ADMIN_SEED_AAD_PREFIX + nodeId);
}

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

function _randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function _utf8Encode(text) {
  return new TextEncoder().encode(text);
}

function _utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}

/** Base64 helpers mirrored from identityBundle.js (shared convention). */
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

function _base64ToBytes(b64) {
  if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
