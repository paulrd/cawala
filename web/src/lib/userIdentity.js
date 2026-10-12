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
 *   - Passkey unlock is an OPTIONAL lock (WebAuthn PRF key-wrap): a passkey
 *     `create` returns a PRF result for a fixed salt, which is run through
 *     HKDF-SHA256 (purpose-bound) into an AES-256-GCM wrap key over the stored
 *     secp256k1 secret. Enrolling removes the plaintext secret (lock on);
 *     unlocking unwraps it for the session only. The PRF output is never
 *     persisted and the passkey is an unlock factor, never a signer.
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
 * True: the WebAuthn PRF key-wrap backend (passkey enroll/unlock) is wired up.
 * Kept as a stable flag for the UI/test surface.
 */
export const PASSKEY_BACKEND_READY = true;

/**
 * Storage record version.
 *
 * v2 adds the derived secp256k1 `secret` (hex). v3 adds the optional `passkey`
 * wrap (`{ credentialId, salt, iv, ct }`) and allows `secret` to be null while
 * the passkey lock is engaged. v2 records stay importable and are migrated in memory (the old `passkeyEnrolled` boolean is dropped: enrollment
 * is now the presence of a wrap). v1 records were the unreleased preview shape
 * (placeholder address, no secret) and are ignored.
 */
export const USER_IDENTITY_VERSION = 3;

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

/**
 * This device/browser cannot do the WebAuthn PRF key-wrap (no PRF result, or
 * `prf.enabled === false`). Deliberately NOT degraded to a weaker gate-only
 * lock: callers surface the honest "use your recovery phrase" path.
 */
export class PasskeyUnsupportedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PasskeyUnsupportedError';
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
 * Whether passkey unlock *could* work here, decided by an explicit origin
 * check rather than `isSecureContext` alone.
 *
 * Per the Secure Contexts spec `file://` is a *potentially trustworthy*
 * origin, so modern browsers set `isSecureContext === true` there and expose
 * `PublicKeyCredential`. WebAuthn still has no valid RP ID for the null
 * `file://` origin, so gating on the secure-context flag alone would render
 * the passkey affordance and then fail inside `enrollPasskey`/
 * `unlockWithPasskey`. Passkeys are therefore limited to `https:` anywhere, or
 * `http:` on a loopback host; on `file://` the mnemonic is the sole unlock
 * path (portable-client refactor spec §1.1/§4).
 *
 * @returns {boolean}
 */
export function isPasskeyAvailable() {
  if (typeof window === 'undefined') return false;
  if (typeof window.PublicKeyCredential !== 'function') return false;
  return _isPasskeyOriginAllowed(window.location);
}

/**
 * The origin predicate behind {@link isPasskeyAvailable}: a WebAuthn RP ID is
 * only well-defined for `https:` (any host) or `http:` on loopback
 * (`localhost` / `127.0.0.1` / `[::1]`). Everything else — including `file:`
 * despite its trustworthy secure-context status — is false.
 *
 * @param {Location|undefined|null} location
 * @returns {boolean}
 */
function _isPasskeyOriginAllowed(location) {
  if (!location) return false;
  const { protocol, hostname } = location;
  if (protocol === 'https:') return true;
  if (protocol !== 'http:') return false;
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
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
    passkeyEnrolled: record.passkey != null,
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
 * The currently installed derived secp256k1 secret, or null when none is
 * available (no identity, or the passkey lock is engaged and the session has
 * not been unlocked).
 *
 * This is the on-device persistence value (hex) that a reload feeds back to
 * the wasm node via `set_user_identity_from_secret`; it is NOT the mnemonic
 * (never stored) and never leaves this device. While a passkey wrap is
 * enrolled the persisted `secret` field is null; a successful unlock installs
 * the secret in memory for the session only (`_sessionSecretBytes`), so a
 * locked device never auto-installs it on boot. `api.js` is the only caller.
 *
 * @returns {Uint8Array|null} 32 raw bytes, or null.
 */
export function getIdentitySecretBytes() {
  const record = _readRecord();
  if (!record) return null;
  return _installedSecretBytes(record);
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
  _sessionSecretBytes = null;
  _writeRecord({
    v: USER_IDENTITY_VERSION,
    address,
    secret: secretHex,
    source: 'created',
    passkey: null,
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
  // The mnemonic is the recovery path: it overrides the passkey lock and
  // re-establishes seamless (plaintext) storage on this device.
  _sessionSecretBytes = null;
  _writeRecord({
    v: USER_IDENTITY_VERSION,
    address,
    secret: secretHex,
    source: 'restored',
    passkey: null,
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

/**
 * Install the R3 identity record from an already-derived secp256k1 secret and
 * its EIP-55 address, WITHOUT the mnemonic. This is the portable identity
 * bundle import path: the bundle carries the derived secret (never the phrase),
 * so a new device/origin restores the same ETH identity and can sign V4
 * orders. The transport seed is restored separately by `api.js`.
 *
 * The mnemonic remains the off-device recovery credential; this device never
 * has it. `source` records that the identity arrived by import.
 *
 * @param {{ address: string, secretHex: string, source?: 'created'|'restored' }} input
 * @returns {object} The `getUserIdentity()` view.
 * @throws {Error} When the address or secret is malformed.
 */
export function adoptIdentity({ address, secretHex, source = 'restored' }) {
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error('The imported identity has an invalid address.');
  }
  if (typeof secretHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(secretHex)) {
    throw new Error('The imported identity has an invalid secret.');
  }
  _sessionSecretBytes = null;
  _writeRecord({
    v: USER_IDENTITY_VERSION,
    address,
    secret: secretHex.toLowerCase(),
    source,
    passkey: null,
    preview: false,
    createdAt: Date.now(),
  });
  return getUserIdentity();
}

// ── Passkey unlock (convenience, never a signer) ──────────────
//
// The passkey is an OPTIONAL lock over the stored secp256k1 secret (spec §1.1):
//   create/get → PRF eval.first(<fixed salt>) → HKDF-SHA256(purpose info) →
//   AES-256-GCM wrap key → encrypt/decrypt the 32-byte secret.
// The PRF output is used in memory only and never persisted. The mnemonic
// remains the sole recovery credential (and the only path on `file://`).

/**
 * Fixed PRF input (`extensions.prf.eval.first`), ≤32 bytes. Stored on the wrap
 * so a future version can rotate it without breaking existing enrollments.
 */
const PASSKEY_PRF_SALT = new TextEncoder().encode('cawala-passkey-prf-v1');

/** Purpose-bound HKDF salt + info (distinct from the PRF input). */
const PASSKEY_HKDF_SALT = new TextEncoder().encode('cawala-passkey-hkdf-v1');
const PASSKEY_WRAP_INFO = new TextEncoder().encode('cawala/passkey-wrap/v1/aes-256-gcm');

/**
 * Secret unwrapped by a successful passkey unlock, installed for this session
 * only (never persisted, so a reload re-locks). Null while locked.
 * @type {Uint8Array|null}
 */
let _sessionSecretBytes = null;

/** PRF capability cache: null undetermined, boolean once known. */
let _prfSupported = null;

/** In-flight PRF capability probe (dedupes concurrent status/enroll calls). */
let _prfProbe = null;

/**
 * Test-only: reset the PRF detection cache and any session-installed secret.
 * Not used by the app.
 */
export function __resetPasskeyStateForTest() {
  _sessionSecretBytes = null;
  _prfSupported = null;
  _prfProbe = null;
}

/** The WebAuthn credentials container, or null outside a browser. */
function _credentials() {
  if (typeof navigator !== 'undefined' && navigator?.credentials) return navigator.credentials;
  return null;
}

/** The `PublicKeyCredential` constructor, or null. */
function _publicKeyCredentialCtor() {
  if (typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function') {
    return window.PublicKeyCredential;
  }
  if (typeof globalThis.PublicKeyCredential === 'function') return globalThis.PublicKeyCredential;
  return null;
}

/**
 * Best-effort PRF capability detection via `PublicKeyCredential.
 * getClientCapabilities()` when the browser exposes it. Resolves null when it
 * cannot decide; the create-time `prf` result then decides.
 *
 * @returns {Promise<boolean|null>}
 */
function _detectPrfSupport() {
  if (_prfSupported !== null) return Promise.resolve(_prfSupported);
  if (_prfProbe) return _prfProbe;
  const ctor = _publicKeyCredentialCtor();
  if (!ctor || typeof ctor.getClientCapabilities !== 'function') {
    return Promise.resolve(null);
  }
  _prfProbe = (async () => {
    try {
      const caps = await ctor.getClientCapabilities();
      if (caps && typeof caps.prf === 'boolean') _prfSupported = caps.prf;
    } catch {
      /* advisory only; the create-time result still decides */
    } finally {
      _prfProbe = null;
    }
    return _prfSupported;
  })();
  return _prfProbe;
}

/** @param {any} credential */
function _prfExtensionResults(credential) {
  try {
    return credential?.getClientExtensionResults?.()?.prf ?? null;
  } catch {
    return null;
  }
}

/**
 * Base64 of a credential's raw id (falling back to its string id).
 * @param {any} credential
 * @returns {string}
 */
function _credentialIdBase64(credential) {
  if (credential?.rawId) {
    const bytes =
      credential.rawId instanceof ArrayBuffer
        ? new Uint8Array(credential.rawId)
        : new Uint8Array(credential.rawId);
    return _bytesToBase64(bytes);
  }
  if (typeof credential?.id === 'string') return credential.id;
  throw new Error('The passkey did not return a credential id.');
}

/**
 * PRF output → HKDF-SHA256(purpose info) → AES-256-GCM CryptoKey.
 * @param {Uint8Array} prfOutput
 * @returns {Promise<CryptoKey>}
 */
async function _deriveWrapKey(prfOutput) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length === 0) {
    throw new PasskeyUnsupportedError(
      'This passkey did not return a WebAuthn PRF result, so it cannot unlock Cawala. Use your recovery phrase instead.',
    );
  }
  const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: PASSKEY_HKDF_SALT, info: PASSKEY_WRAP_INFO },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * @param {Uint8Array} prfOutput
 * @param {Uint8Array} secretBytes
 * @returns {Promise<{ iv: string, ct: string }>}
 */
async function _wrapSecret(prfOutput, secretBytes) {
  const key = await _deriveWrapKey(prfOutput);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secretBytes),
  );
  return { iv: _bytesToBase64(iv), ct: _bytesToBase64(ct) };
}

/**
 * @param {Uint8Array} prfOutput
 * @param {{ iv: string, ct: string }} wrap
 * @returns {Promise<Uint8Array>}
 * @throws {Error} On an AES-GCM authentication failure (wrong PRF output).
 */
async function _unwrapSecret(prfOutput, wrap) {
  const key = await _deriveWrapKey(prfOutput);
  const iv = _base64ToBytes(wrap.iv);
  const ct = _base64ToBytes(wrap.ct);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(plain);
}

/** Create a passkey with the PRF extension evaluated at the given salt. */
async function _createPasskeyCredential(prfSalt) {
  const credentials = _credentials();
  if (!credentials || typeof credentials.create !== 'function') {
    throw new PasskeyUnavailableError(
      'This browser does not expose passkey creation. Use your recovery phrase instead.',
    );
  }
  return credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'Cawala' },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: 'Cawala identity',
        displayName: 'Cawala identity',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      timeout: 120000,
      attestation: 'none',
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
}

/** Assert the stored credential and read its PRF result for the given salt. */
async function _assertPasskey(credentialIdB64, prfSalt) {
  const credentials = _credentials();
  if (!credentials || typeof credentials.get !== 'function') {
    throw new PasskeyUnavailableError(
      'This browser does not expose passkey unlock. Use your recovery phrase instead.',
    );
  }
  let id;
  try {
    id = _base64ToBytes(credentialIdB64);
  } catch {
    throw new PasskeyUnavailableError('The stored passkey reference is unreadable.');
  }
  return credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id }],
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
}

/**
 * Resolve the PRF output for a freshly created credential: prefer the
 * create-time `prf.results.first`, else assert once (some authenticators only
 * advertise `enabled` at creation).
 *
 * @param {any} credential
 * @param {Uint8Array} prfSalt
 * @returns {Promise<Uint8Array>}
 * @throws {PasskeyUnsupportedError} On `prf.enabled === false` / no PRF result.
 */
async function _prfOutputFromCreate(credential, prfSalt) {
  const prf = _prfExtensionResults(credential);
  if (prf?.enabled === false) {
    _prfSupported = false;
    throw new PasskeyUnsupportedError(
      'This device cannot create a passkey with WebAuthn PRF, so biometric unlock is not available. Use your recovery phrase instead.',
    );
  }
  const first = prf?.results?.first;
  if (first) {
    _prfSupported = true;
    return new Uint8Array(first);
  }
  return _prfOutputFromAssertion(_credentialIdBase64(credential), prfSalt);
}

/**
 * Assert the stored credential and resolve its PRF output.
 *
 * @param {string} credentialIdB64
 * @param {Uint8Array} prfSalt
 * @returns {Promise<Uint8Array>}
 * @throws {PasskeyUnsupportedError} When no PRF result is returned.
 */
async function _prfOutputFromAssertion(credentialIdB64, prfSalt) {
  const assertion = await _assertPasskey(credentialIdB64, prfSalt);
  const prf = _prfExtensionResults(assertion);
  if (prf?.enabled === false) _prfSupported = false;
  const first = prf?.results?.first;
  if (first) {
    _prfSupported = true;
    return new Uint8Array(first);
  }
  throw new PasskeyUnsupportedError(
    'This passkey did not return a WebAuthn PRF result, so it cannot unlock Cawala. Use your recovery phrase instead.',
  );
}

/**
 * Decode the PRF salt stored on a wrap; fall back to the fixed default for a
 * missing/corrupt value (a mismatched salt simply fails the unwrap, fail-closed).
 *
 * @param {unknown} saltB64
 * @returns {Uint8Array}
 */
function _decodeStoredSalt(saltB64) {
  if (typeof saltB64 === 'string') {
    try {
      const bytes = _base64ToBytes(saltB64);
      if (bytes.length > 0) return bytes;
    } catch {
      /* fall through to the default */
    }
  }
  return PASSKEY_PRF_SALT;
}

/**
 * The secret currently usable on this device: the session-installed one (after
 * a passkey unlock) or the persisted plaintext (seamless storage). Null when
 * locked.
 *
 * @param {object|null} record
 * @returns {Uint8Array|null}
 */
function _installedSecretBytes(record) {
  if (_sessionSecretBytes) return _sessionSecretBytes;
  const hex = record?.secret;
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  try {
    return _hexToBytes(hex);
  } catch {
    return null;
  }
}

/**
 * The passkey-lock status the identity UI renders from. Never carries key
 * material.
 *
 * `available` is the secure-origin + WebAuthn check; `prfSupported` is
 * `true`/`false` once determined and `null` until then; `enrolled` is a stored
 * wrap for this identity; `locked` means enrolled but the secret is not
 * currently installed (a passkey unlock or mnemonic restore is needed).
 *
 * @returns {{ available: boolean, prfSupported: boolean|null, enrolled: boolean, locked: boolean }}
 */
export function getPasskeyStatus() {
  const available = isPasskeyAvailable();
  const record = _readRecord();
  const enrolled = Boolean(record?.passkey);
  const locked = enrolled && _installedSecretBytes(record) === null;
  // Kick off the advisory capability probe so a later call can report it.
  if (available && _prfSupported === null) void _detectPrfSupport();
  return { available, prfSupported: _prfSupported, enrolled, locked };
}

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
 * Set up biometric unlock: create a passkey with the PRF extension, derive a
 * wrap key from the PRF result, AES-256-GCM-wrap the stored secp256k1 secret,
 * then remove the plaintext secret (the lock engages immediately). The passkey
 * is an unlock factor and never signs.
 *
 * @returns {Promise<object>} The `getUserIdentity()` view.
 * @throws {PasskeyUnavailableError|PasskeyUnsupportedError}
 */
export async function enrollPasskey() {
  if (!isPasskeyAvailable()) {
    throw new PasskeyUnavailableError(
      'Passkeys need a secure connection (https or localhost). This page isn’t one, so biometric unlock is not offered here.',
    );
  }
  const record = _readRecord();
  if (!record) {
    throw new Error('Create or restore an identity first.');
  }
  const secret = _installedSecretBytes(record);
  if (!secret) {
    throw new PasskeyUnavailableError(
      'Unlock with your passkey or your recovery phrase before changing biometric unlock.',
    );
  }

  // Do not silently degrade to a weaker gate-only lock: refuse when PRF is
  // known to be unsupported.
  if ((await _detectPrfSupport()) === false) {
    throw new PasskeyUnsupportedError(
      'This device does not support WebAuthn PRF, so biometric unlock is not available. Use your recovery phrase instead.',
    );
  }

  const credential = await _createPasskeyCredential(PASSKEY_PRF_SALT);
  const credentialId = _credentialIdBase64(credential);
  const prfOutput = await _prfOutputFromCreate(credential, PASSKEY_PRF_SALT);
  const { iv, ct } = await _wrapSecret(prfOutput, secret);

  // Lock on: persist the wrap and drop the plaintext secret everywhere.
  _sessionSecretBytes = null;
  _writeRecord({
    ...record,
    v: USER_IDENTITY_VERSION,
    secret: null,
    passkey: {
      credentialId,
      salt: _bytesToBase64(PASSKEY_PRF_SALT),
      iv,
      ct,
    },
  });
  return getUserIdentity();
}

/**
 * Unlock with the enrolled passkey: assert → PRF → HKDF → AES-256-GCM unwrap →
 * install the secret for this session. A failed assertion or a wrap-key
 * mismatch leaves the locked record untouched.
 *
 * @returns {Promise<object>} The `getUserIdentity()` view.
 * @throws {PasskeyUnavailableError|PasskeyUnsupportedError|Error}
 */
export async function unlockWithPasskey() {
  if (!isPasskeyAvailable()) {
    throw new PasskeyUnavailableError(
      'Passkeys need a secure connection (https or localhost), so this device can’t unlock that way here.',
    );
  }
  const record = _readRecord();
  if (!record) throw new Error('No identity to unlock.');
  const wrap = record.passkey;
  if (!wrap) {
    throw new PasskeyUnavailableError('No passkey is set up for this identity yet.');
  }

  const prfOutput = await _prfOutputFromAssertion(wrap.credentialId, _decodeStoredSalt(wrap.salt));
  let secret;
  try {
    secret = await _unwrapSecret(prfOutput, wrap);
  } catch {
    throw new Error(
      'Passkey unlock failed: this device’s passkey did not match. Try again, or restore with your recovery phrase.',
    );
  }
  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new Error('Passkey unlock produced an invalid secret; nothing was changed.');
  }
  _sessionSecretBytes = secret;
  return getUserIdentity();
}

/**
 * Remove the enrolled passkey while unlocked: write the plaintext secret back
 * to seamless storage and clear the wrap. The recovery phrase is unaffected.
 *
 * Trade-off: seamless storage (no passkey) means a reload needs no unlock, so
 * anyone with this browser profile can use the identity. The passkey lock is
 * the opt-in protection against exactly that.
 *
 * @returns {Promise<object>} The `getUserIdentity()` view.
 * @throws {PasskeyUnavailableError} While the identity is locked.
 */
export async function removePasskey() {
  const record = _readRecord();
  if (!record) throw new Error('No identity on this device.');
  if (!record.passkey) return getUserIdentity(); // already seamless

  const secret = _installedSecretBytes(record);
  if (!secret) {
    throw new PasskeyUnavailableError('Unlock with your passkey first, then you can remove it.');
  }
  _writeRecord({
    ...record,
    v: USER_IDENTITY_VERSION,
    secret: _bytesToHex(secret),
    passkey: null,
  });
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
 * @returns {Promise<{ address: string, secretHex: string, secretBytes: Uint8Array }>}
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
  return { address, secretHex: _bytesToHex(secret), secretBytes: secret };
}

/**
 * Derive a mnemonic's EIP-55 address AND its raw secp256k1 secret WITHOUT
 * persisting anything.
 *
 * The rotation flow needs both: the address names the new anchor and the secret
 * is handed to the wasm node so it can prove control. Nothing is written here,
 * so a rejected rotation leaves the incumbent identity intact.
 *
 * @param {string} mnemonic
 * @param {string} [passphrase='']
 * @returns {Promise<{ address: string, secretHex: string, secretBytes: Uint8Array }>}
 * @throws {InvalidMnemonicError|IdentityBackendUnavailableError}
 */
export async function deriveIdentityAddressAndSecret(mnemonic, passphrase = '') {
  return _deriveAddressAndSecret(mnemonic, passphrase);
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
  __resetPasskeyStateForTest();
}

/** Record versions this build can import (older ones migrate in memory). */
const SUPPORTED_RECORD_VERSIONS = new Set([USER_IDENTITY_VERSION, 2]);

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
    if (parsed === null || typeof parsed !== 'object') return null;
    if (!SUPPORTED_RECORD_VERSIONS.has(parsed.v)) return null;
    if (typeof parsed.address !== 'string') return null;
    return _migrateRecord(parsed);
  } catch {
    return null;
  }
}

/**
 * Normalize a stored record to the current version. v2 → v3 drops the old
 * `passkeyEnrolled` boolean: enrollment is now the presence of the `passkey`
 * wrap, and v2 never carried one (the released stub refused to enroll).
 *
 * @param {object} record
 * @returns {object}
 */
function _migrateRecord(record) {
  if (record.v === USER_IDENTITY_VERSION) return record;
  const migrated = {
    ...record,
    v: USER_IDENTITY_VERSION,
    passkey: record.passkey ?? null,
  };
  delete migrated.passkeyEnrolled;
  return migrated;
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

function _removeRecord() {
  _memoryRecord = null;
  _memoryOnly = false;
  _sessionSecretBytes = null;
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

/**
 * @param {Uint8Array} bytes
 * @returns {string} standard base64
 */
function _bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * @param {string} b64 standard base64
 * @returns {Uint8Array}
 * @throws {Error} On malformed base64.
 */
function _base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// Re-exported so callers need only one import for error-code comparisons.
export { MNEMONIC_ERRORS };
