/**
 * Cawala — user identity facade (R3 surface, UI side).
 *
 * One user identity = a secp256k1 Ethereum address derived from a BIP-39
 * mnemonic (spec §1.1). The mnemonic is the root of trust and the only
 * recovery credential; a passkey is an *unlock convenience* that never signs
 * and cannot replace the phrase. The browser's transport key is derived from
 * the same mnemonic — context the user does not manage.
 *
 * ── BACKEND STATUS (spec P2b-web) ─────────────────────────────────────
 * Address derivation now runs the real wasm secp256k1/BIP-39 engine
 * (`UserIdentity.fromMnemonic`), injected by `api.js` after wasm init via
 * `setIdentityBackend({ deriveAddress, secretBytes, transportSeed })`. The
 * facade never imports wasm itself, so it stays loadable on plain Node for
 * `node --test`; tests inject a mock backend.
 *   - Mnemonic generation/validation are REAL (pure BIP-39 in `bip39.js`).
 *   - The derived secp256k1 secret is persisted on-device (hex) so a reload
 *     needs no unlock; the mnemonic itself is never stored.
 *   - Passkey enroll/unlock stay honestly stubbed (`PASSKEY_BACKEND_READY`
 *     is false) until the WebAuthn PRF key-wrap lands; the passkey is an
 *     unlock factor, never a signer.
 *
 * The public function names/signatures here ARE the api surface `api.js`
 * re-exports.
 *
 * Pure ESM, no DOM requirement — guarded storage and feature detection make
 * it loadable on plain Node for `node --test`.
 */

import { validateMnemonic, generateMnemonic, MNEMONIC_ERRORS } from './bip39.js';
import { STORAGE_KEYS } from './storage.js';

/**
 * True: the wasm crypto engine derives real EIP-55 addresses and yields the
 * secp256k1 secret. Kept as a stable flag for the UI/test surface.
 */
export const USER_IDENTITY_BACKEND_READY = true;

/**
 * False: the WebAuthn PRF key-wrap backend (passkey enroll/unlock) is a
 * separate, deferred sub-lane. Passkey actions report honestly until then.
 */
export const PASSKEY_BACKEND_READY = false;

/**
 * Storage record version.
 *
 * v2 adds the derived secp256k1 `secret` (hex). v1 records were the
 * unreleased preview shape (placeholder address, no secret) and are ignored.
 */
export const USER_IDENTITY_VERSION = 2;

// ── Errors (stable shapes the UI maps to copy) ────────────────

/** The mnemonic failed BIP-39 validation. `code` is `MNEMONIC_ERRORS.*`. */
export class InvalidMnemonicError extends Error {
  /**
   * @param {{ code: string, message: string, wordIndex?: number }} detail
   */
  constructor(detail) {
    super(detail.message);
    this.name = 'InvalidMnemonicError';
    this.code = detail.code;
    this.wordIndex = detail.wordIndex ?? null;
  }
}

/** Passkey control used in a context that cannot have one (e.g. `file://`). */
export class PasskeyUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PasskeyUnavailableError';
  }
}

/** The crypto backend is not connected yet — honest "not wired up" path. */
export class IdentityBackendUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'IdentityBackendUnavailableError';
  }
}

// ── Injected crypto backend (api.js owns wasm loading) ────────

/**
 * The wasm-backed crypto operations this facade needs. `api.js` builds this
 * after wasm init and injects it with `setIdentityBackend`, so this module
 * never imports wasm and stays unit-testable on plain Node (tests inject a
 * mock). All three functions receive an already-normalized mnemonic and the
 * optional BIP-39 passphrase.
 *
 * @typedef {{
 *   deriveAddress: (mnemonic: string, passphrase: string) => (string|Promise<string>),
 *   secretBytes: (mnemonic: string, passphrase: string) => (Uint8Array|Promise<Uint8Array>),
 *   transportSeed: (mnemonic: string, passphrase: string) => (Uint8Array|Promise<Uint8Array>),
 * }} IdentityCryptoBackend
 */

/** @type {IdentityCryptoBackend|null} */
let _backend = null;

/**
 * Wire the real wasm crypto engine into this facade. Called by `api.js` once
 * (after `initApi` loads wasm); callable from tests with a mock. Never
 * persists anything.
 *
 * @param {IdentityCryptoBackend} backend
 */
export function setIdentityBackend(backend) {
  _backend = backend ?? null;
}

/**
 * Test-only: clear the injected backend (restores the honest "not connected"
 * path). Not used by the app.
 */
export function __resetIdentityBackendForTest() {
  _backend = null;
}

/**
 * @returns {IdentityCryptoBackend}
 * @throws {IdentityBackendUnavailableError} When wasm has not been injected.
 */
function _requireBackend() {
  if (!_backend) {
    throw new IdentityBackendUnavailableError(
      'The crypto engine has not finished loading yet. Reload the page and try again.',
    );
  }
  return _backend;
}

/**
 * Derive the deterministic Ed25519 transport seed from a mnemonic (+ optional
 * BIP-39 passphrase). The same phrase restores this browser's NodeId/operator
 * key on any host (Addendum B/C §6). `api.js` persists the result under
 * `cawala.identity.v1` at create/restore time; it is never derived on load
 * (a stored seed is preserved).
 *
 * @param {string} mnemonic
 * @param {string} [passphrase='']
 * @returns {Promise<Uint8Array>} 32-byte Ed25519 seed.
 * @throws {InvalidMnemonicError} On a bad phrase.
 */
export async function deriveTransportSeed(mnemonic, passphrase = '') {
  const validation = await validateMnemonic(mnemonic);
  if (!validation.ok) throw new InvalidMnemonicError(validation.error);
  return _requireBackend().transportSeed(validation.normalized, passphrase ?? '');
}

// ── Feature detection ─────────────────────────────────────────

/**
 * Whether passkey unlock *could* work here: a secure context (https or
 * localhost) exposing the WebAuthn API. On `file://` (and plain http on a
 * non-localhost host) this is false and the passkey UI stays hidden.
 *
 * @returns {boolean}
 */
export function isPasskeyAvailable() {
  if (typeof window === 'undefined') return false;
  if (window.isSecureContext !== true) return false;
  return typeof window.PublicKeyCredential === 'function';
}

// ── Status ────────────────────────────────────────────────────

/**
 * The identity status the UI renders from. Never carries the mnemonic.
 *
 * @returns {{ established: boolean, address: string|null, source: 'created'|'restored'|null, passkeyEnrolled: boolean, preview: boolean, createdAt: number|null, storagePersistent: boolean }}
 */
export function getUserIdentity() {
  const record = _readRecord();
  if (!record) {
    return {
      established: false,
      address: null,
      source: null,
      passkeyEnrolled: false,
      preview: false,
      createdAt: null,
      storagePersistent: _storageAvailable(),
    };
  }
  return {
    established: true,
    address: record.address ?? null,
    source: record.source ?? null,
    passkeyEnrolled: record.passkeyEnrolled === true,
    preview: record.preview === true,
    createdAt: record.createdAt ?? null,
    storagePersistent: _storageAvailable(),
  };
}

/**
 * The EIP-55 checksummed account address, or null when no identity exists.
 * @returns {string|null}
 */
export function getEthAddress() {
  return _readRecord()?.address ?? null;
}

/**
 * The persisted derived secp256k1 secret, or null when none is stored.
 *
 * This is the on-device persistence value (hex) that a reload feeds back to
 * the wasm node via `set_user_identity_from_secret`; it is NOT the mnemonic
 * (never stored) and never leaves this device. `api.js` is the only caller.
 *
 * @returns {Uint8Array|null} 32 raw bytes, or null.
 */
export function getIdentitySecretBytes() {
  const hex = _readRecord()?.secret;
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  try {
    return _hexToBytes(hex);
  } catch {
    return null;
  }
}

// ── Mnemonic flow ─────────────────────────────────────────────

/**
 * Generate a fresh 12-word BIP-39 mnemonic (128-bit entropy).
 * The UI shows it once for backup; this module never persists it.
 *
 * @returns {Promise<string>} Space-joined words.
 */
export async function generateIdentityMnemonic() {
  return generateMnemonic(128);
}

/**
 * Validate free-typed mnemonic text. Delegates to `bip39.validateMnemonic`;
 * re-exported here so the whole identity surface has one entry point.
 *
 * @param {string} text
 * @returns {Promise<{ ok: boolean, words: string[], normalized: string, error: { code: string, message: string, wordIndex?: number }|null }>}
 */
export async function validateIdentityMnemonic(text) {
  return validateMnemonic(text);
}

/**
 * Derive the account address WITHOUT persisting anything: the restore
 * preview, and the address step of the create flow.
 *
 * @param {string} mnemonic
 * @param {string} [passphrase=''] Optional BIP-39 passphrase.
 * @returns {Promise<{ address: string, preview: boolean }>}
 * @throws {InvalidMnemonicError} On a bad phrase.
 */
export async function previewIdentity(mnemonic, passphrase = '') {
  const address = await _deriveEthAddress(mnemonic, passphrase);
  return { address, preview: false };
}

/**
 * Create a new identity: generate (or accept) a 12-word mnemonic, derive the
 * address, and persist the resulting record. The mnemonic itself is never
 * stored — the caller shows it once for the user to write down.
 *
 * @param {{ mnemonic?: string, passphrase?: string }} [input] Omit `mnemonic`
 *   to let this function generate one (returned in `inputMnemonic`).
 * @returns {Promise<{ status: object, inputMnemonic: string|null }>} `status`
 *   is the `getUserIdentity()` view; `inputMnemonic` is set only when this
 *   call generated the phrase (so the UI can show it for backup).
 * @throws {InvalidMnemonicError} On a bad supplied phrase.
 */
export async function createIdentity({ mnemonic, passphrase = '' } = {}) {
  let supplied = typeof mnemonic === 'string' ? mnemonic : null;
  let generated = null;
  if (supplied == null) {
    generated = await generateIdentityMnemonic();
    supplied = generated;
  }
  // Validates (throws InvalidMnemonicError) and derives the address + secret.
  const { address, secretHex } = await _deriveAddressAndSecret(supplied, passphrase);
  _writeRecord({
    v: USER_IDENTITY_VERSION,
    address,
    secret: secretHex,
    source: 'created',
    passkeyEnrolled: false,
    preview: false,
    createdAt: Date.now(),
  });
  return { status: getUserIdentity(), inputMnemonic: generated };
}

/**
 * Restore an identity from a mnemonic (optional BIP-39 passphrase): validate,
 * derive the address, persist. Replaces any identity already on this device —
 * the caller is responsible for an explicit confirmation.
 *
 * @param {string} mnemonic
 * @param {string} [passphrase='']
 * @returns {Promise<object>} The `getUserIdentity()` view.
 * @throws {InvalidMnemonicError} On a bad phrase — nothing is persisted.
 */
export async function restoreIdentity(mnemonic, passphrase = '') {
  const { address, secretHex } = await _deriveAddressAndSecret(mnemonic, passphrase);
  _writeRecord({
    v: USER_IDENTITY_VERSION,
    address,
    secret: secretHex,
    source: 'restored',
    passkeyEnrolled: false,
    preview: false,
    createdAt: Date.now(),
  });
  return getUserIdentity();
}

/**
 * Forget the identity record on this device (used by `wipeIdentity`). Removes
 * the derived secp256k1 secret along with the record; the recovery phrase was
 * never stored, so the phrase remains the user's off-device recovery
 * credential.
 */
export function clearUserIdentity() {
  _removeRecord();
}

// ── Passkey unlock (convenience, never a signer) ──────────────

/**
 * Whether a passkey is set up for this identity in a context where passkeys
 * work. False on `file://` / insecure origins and before enrollment.
 *
 * @returns {Promise<boolean>}
 */
export async function hasPasskey() {
  if (!isPasskeyAvailable()) return false;
  return getUserIdentity().passkeyEnrolled;
}

/**
 * Set up biometric unlock: create a passkey and use its PRF output to
 * key-wrap the mnemonic (spec §1.1). Needs the crypto backend.
 *
 * @returns {Promise<object>} The `getUserIdentity()` view.
 * @throws {PasskeyUnavailableError|IdentityBackendUnavailableError}
 */
export async function enrollPasskey() {
  if (!isPasskeyAvailable()) {
    throw new PasskeyUnavailableError(
      'Passkeys need a secure connection (https or localhost). This page isn’t one, so biometric unlock is not offered here.',
    );
  }
  const status = getUserIdentity();
  if (!status.established) {
    throw new Error('Create or restore an identity first.');
  }
  if (!PASSKEY_BACKEND_READY) {
    throw new IdentityBackendUnavailableError(
      'Biometric unlock arrives with the crypto update (WebAuthn PRF + key wrap). This build can show the flow but cannot store a passkey yet — your recovery phrase still works.',
    );
  }
  // Backend path (not reachable until PASSKEY_BACKEND_READY):
  //   WebAuthn create() with the prf extension → HKDF → AES-256-GCM key wrap
  //   of the mnemonic → persist `wrap` on the record. Never store the phrase
  //   in readable form, and never treat the passkey as a signer.
  _setPasskeyEnrolled(true);
  return getUserIdentity();
}

/**
 * Unlock with the enrolled passkey (PRF → unwrap → mnemonic → address).
 *
 * @returns {Promise<object>} The `getUserIdentity()` view.
 * @throws {PasskeyUnavailableError|IdentityBackendUnavailableError}
 */
export async function unlockWithPasskey() {
  if (!isPasskeyAvailable()) {
    throw new PasskeyUnavailableError(
      'Passkeys need a secure connection (https or localhost), so this device can’t unlock that way here.',
    );
  }
  const status = getUserIdentity();
  if (!status.established) {
    throw new Error('No identity to unlock.');
  }
  if (!status.passkeyEnrolled) {
    throw new PasskeyUnavailableError('No passkey is set up for this identity yet.');
  }
  if (!PASSKEY_BACKEND_READY) {
    throw new IdentityBackendUnavailableError(
      'Biometric unlock arrives with the crypto update (WebAuthn PRF + key wrap). This build cannot complete the unlock yet — your recovery phrase still works.',
    );
  }
  return getUserIdentity();
}

/**
 * Remove the enrolled passkey from this device. The recovery phrase is
 * unaffected.
 *
 * @returns {Promise<object>} The `getUserIdentity()` view.
 */
export async function removePasskey() {
  if (!getUserIdentity().established) {
    throw new Error('No identity on this device.');
  }
  _setPasskeyEnrolled(false);
  return getUserIdentity();
}

// ── Address / secret derivation (via the injected wasm backend) ─

/**
 * Mnemonic (+ optional passphrase) → EIP-55 address, through the real wasm
 * secp256k1 path (`UserIdentity.fromMnemonic(...).address()`), injected by
 * `api.js`.
 *
 * @param {string} mnemonic
 * @param {string} passphrase
 * @returns {Promise<string>} EIP-55 checksummed `0x…` address.
 * @throws {InvalidMnemonicError} On a bad phrase.
 * @throws {IdentityBackendUnavailableError} When wasm is not injected yet.
 */
async function _deriveEthAddress(mnemonic, passphrase) {
  const validation = await validateMnemonic(mnemonic);
  if (!validation.ok) {
    throw new InvalidMnemonicError(validation.error);
  }
  try {
    return await _requireBackend().deriveAddress(validation.normalized, passphrase ?? '');
  } catch (err) {
    if (err instanceof IdentityBackendUnavailableError) throw err;
    // The JS BIP-39 check passed but the wasm engine refused it (e.g. a
    // wordlist/locale mismatch): surface it as an invalid phrase, not a crash.
    throw new InvalidMnemonicError({
      code: MNEMONIC_ERRORS.CHECKSUM,
      message: 'That phrase could not be derived into an account. Check the words and try again.',
    });
  }
}

/**
 * Validate once, then derive BOTH the EIP-55 address and the raw secp256k1
 * secret the record persists. Kept in one place so create/restore cannot
 * diverge on normalization.
 *
 * @param {string} mnemonic
 * @param {string} passphrase
 * @returns {Promise<{ address: string, secretHex: string }>}
 * @throws {InvalidMnemonicError|IdentityBackendUnavailableError}
 */
async function _deriveAddressAndSecret(mnemonic, passphrase) {
  const validation = await validateMnemonic(mnemonic);
  if (!validation.ok) {
    throw new InvalidMnemonicError(validation.error);
  }
  const backend = _requireBackend();
  let address;
  let secret;
  try {
    address = await backend.deriveAddress(validation.normalized, passphrase ?? '');
    secret = await backend.secretBytes(validation.normalized, passphrase ?? '');
  } catch (err) {
    if (err instanceof IdentityBackendUnavailableError) throw err;
    throw new InvalidMnemonicError({
      code: MNEMONIC_ERRORS.CHECKSUM,
      message: 'That phrase could not be derived into an account. Check the words and try again.',
    });
  }
  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new Error('The crypto engine returned an unexpected secret length.');
  }
  return { address, secretHex: _bytesToHex(secret) };
}

// ── Storage (guarded; memory fallback keeps tests/Node working) ─────────

/** In-memory record: used when localStorage is unavailable or absent. */
let _memoryRecord = null;

/** True when the last write could only land in memory (quota / private mode). */
let _memoryOnly = false;

/** Test seam: inject a localStorage-like object, or null for memory-only. */
let _injectedStore = undefined;

export function __setStorageForTest(store) {
  _injectedStore = store;
  _memoryRecord = null;
  _memoryOnly = false;
}

/**
 * @returns {object|null} The raw stored record, or null.
 */
function _readRecord() {
  const store = _resolveStore();
  if (!store) return _memoryRecord;
  let raw;
  try {
    raw = store.getItem(STORAGE_KEYS.USER_IDENTITY);
  } catch {
    return _memoryRecord; // storage denied mid-session → session memory
  }
  if (raw == null) {
    // Storage is present and authoritative: an externally cleared store reads
    // as cleared, unless our own last write could only go to memory.
    if (!_memoryOnly) _memoryRecord = null;
    return _memoryOnly ? _memoryRecord : null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== 'object' || parsed.v !== USER_IDENTITY_VERSION) {
      return null;
    }
    if (typeof parsed.address !== 'string') return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Persist the record. Falls back to memory when storage throws; never throws.
 * @param {object} record
 */
function _writeRecord(record) {
  _memoryRecord = record;
  const store = _resolveStore();
  if (!store) {
    _memoryOnly = true;
    return;
  }
  try {
    store.setItem(STORAGE_KEYS.USER_IDENTITY, JSON.stringify(record));
    _memoryOnly = false;
  } catch {
    // Private mode / quota: the record survives in memory for this session.
    _memoryOnly = true;
  }
}

function _setPasskeyEnrolled(value) {
  const record = _readRecord();
  if (!record) return;
  _writeRecord({ ...record, passkeyEnrolled: !!value });
}

function _removeRecord() {
  _memoryRecord = null;
  _memoryOnly = false;
  const store = _resolveStore();
  if (!store) return;
  try {
    store.removeItem(STORAGE_KEYS.USER_IDENTITY);
  } catch {
    /* ignore */
  }
}

/** Whether a usable (non-memory) storage exists right now. */
function _storageAvailable() {
  return _resolveStore() !== null;
}

/**
 * Resolve a localStorage-like object: test injection → window → globalThis.
 * Returns null on plain Node / denied access.
 * @returns {any|null}
 */
function _resolveStore() {
  if (_injectedStore !== undefined) return _injectedStore;
  try {
    if (typeof window !== 'undefined' && window.localStorage) return window.localStorage;
  } catch {
    /* private mode / denied */
  }
  try {
    if (typeof globalThis !== 'undefined' && globalThis.localStorage) return globalThis.localStorage;
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string} lowercase hex
 */
function _bytesToHex(bytes) {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/**
 * @param {string} hex even-length lowercase/uppercase hex
 * @returns {Uint8Array}
 * @throws {Error} On malformed hex.
 */
function _hexToBytes(hex) {
  const clean = String(hex).trim().toLowerCase();
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/.test(clean)) {
    throw new Error('malformed hex');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

// Re-exported so callers need only one import for error-code comparisons.
export { MNEMONIC_ERRORS };
