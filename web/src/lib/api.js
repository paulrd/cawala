/**
 * Cawala M4 — API adapter (single boundary between UI and WASM/control layer).
 *
 * ALL calls to the wasm client and control message layer go through this module.
 * Components never import from ../wasm/ directly.
 *
 * Live ("A′ user-live") mode:
 *   - By default `initApi()` dynamically loads the wasm client, restores (or
 *     generates) a stable Ed25519 identity, spawns a control node via
 *     `ClientNode.spawn_control`, restores any persisted state, and sets
 *     `_useMock = false`. A 2 s poller drains control events (JoinApproved /
 *     JoinRejected) and persists state.
 *   - Admin mode (R6) is locked by default. Unlocking records a policy
 *     acknowledgement and discovers this browser's ancestor chain
 *     (`discover_admin_targets`); every admin read/write then targets one of
 *     those ancestors, chosen with the up/down control (R7) rather than a
 *     dropdown. Nothing about the unlock survives a reload.
 *
 * Mock mode:
 *   - When `?mock` is in the URL, or when wasm init fails for any reason,
 *     every function returns plausible fake data so the UI can be developed
 *     and reviewed without a live node. The module-level `_useMock` contract
 *     is preserved.
 */

import {
  CONNECTION,
  ACTIVITY_TYPES,
  ACTIVITY_LABELS,
  ENVELOPE_ACK,
  JOIN_STATE,
  JOIN_OUTCOME,
  CONTROL_EVENT,
  LEDGER_EVENT,
  ORDER_STATUS,
} from './constants.js';
import {
  clientState,
  ledgerState,
  apiCapabilities,
  administeredNode,
  adminCapabilities,
  adminLock,
  applyAdministeredNode,
  applyAdminCapabilities,
  applyAdminLock,
  applyUserIdentity,
  resetDataState,
  bumpTargetEpoch,
  showToast,
} from './stores.svelte.js';
import { NODE_KIND, inferNodeKind } from './nodeKind.js';
import * as idb from './identityBundle.js';
import * as parentLiveness from './parentLiveness.js';
import { SELF_ID as SELF, MOCK_ID as MOCK_NODE_ID } from './adminView.js';
import {
  POLICY_TEXT,
  POLICY_HASH,
  readAcknowledgedPolicy,
  writeAcknowledgedPolicy,
} from './adminPolicy.js';
import {
  STORAGE_KEYS,
  readScopedBlob,
  restoreBlobs,
} from './storage.js';
import * as userIdentity from './userIdentity.js';

// ── User identity (R3) — the surface the identity UI calls ────
//
// The mnemonic → ETH-address identity (spec §1.1). These functions are thin
// wrappers over `userIdentity.js`: they keep the reactive
// `userIdentityState` store in sync after every mutation, so components read
// the store and only call these on user actions. Address derivation and the
// derived secret now run the REAL wasm secp256k1 engine, injected into the
// facade after `initApi` loads wasm (`_wasmIdentityBackend` below). The
// passkey wrap stays deferred (`PASSKEY_BACKEND_READY === false`).
//
// CREATE/RESTORE also do two wasm-side things here (this module owns the
// ClientNode lifecycle and `cawala.identity.v1`):
//   1. derive + persist the mnemonic-derived transport seed so one phrase
//      restores the NodeId; on a fresh install the live node is then
//      RE-SPAWNED with that seed immediately (see `_reactivateTransportIdentity`)
//      so its NodeId matches the phrase before any join/registration, and
//   2. push the derived secp256k1 secret into the live node so V4 orders can
//      be signed without a reload.
//
// ASSUMED API SURFACE (keep names/signatures, swap bodies):

/** Re-exported identity errors + BIP-39 error codes for `instanceof`/mapping. */
export const {
  InvalidMnemonicError,
  PasskeyUnavailableError,
  IdentityBackendUnavailableError,
  MNEMONIC_ERRORS,
} = userIdentity;

/**
 * Re-read the stored identity into the reactive store. Called at boot and
 * after every identity mutation; safe to call any time.
 */
export function refreshUserIdentity() {
  applyUserIdentity(userIdentity.getUserIdentity());
}

/** Whether passkey unlock could work in this context (secure context + WebAuthn). */
export function isPasskeyAvailable() {
  return userIdentity.isPasskeyAvailable();
}

/**
 * The identity status view: `{ established, address, source,
 * passkeyEnrolled, preview, createdAt, storagePersistent }`.
 */
export function getUserIdentity() {
  return userIdentity.getUserIdentity();
}

/** EIP-55 checksummed account address, or null when none exists here. */
export function getEthAddress() {
  return userIdentity.getEthAddress();
}

/**
 * Generate a fresh 12-word BIP-39 mnemonic (shown once for backup; never
 * persisted by this module).
 * @returns {Promise<string>} Space-joined words.
 */
export function generateMnemonic() {
  return userIdentity.generateIdentityMnemonic();
}

/**
 * Validate free-typed mnemonic text (async; structured result with
 * `MNEMONIC_ERRORS.*` codes for word-level feedback).
 * @param {string} text
 */
export function validateMnemonic(text) {
  return userIdentity.validateIdentityMnemonic(text);
}

/**
 * Derive the address from a mnemonic (+ optional BIP-39 passphrase) WITHOUT
 * persisting — the restore preview / pre-commit check.
 * @param {string} mnemonic
 * @param {string} [passphrase='']
 * @returns {Promise<{ address: string, preview: boolean }>}
 */
export function previewIdentity(mnemonic, passphrase = '') {
  return userIdentity.previewIdentity(mnemonic, passphrase);
}

/**
 * Create a new identity (generates the mnemonic when `mnemonic` is omitted).
 * @param {{ mnemonic?: string, passphrase?: string }} [input]
 * @returns {Promise<{ status: object, inputMnemonic: string|null }>}
 */
export async function createIdentity(input = {}) {
  const result = await userIdentity.createIdentity(input);
  refreshUserIdentity();
  // If this call generated the phrase, `input.mnemonic` is absent; the facade
  // returns it for backup and that is the phrase the secrets derive from.
  const mnemonic = input.mnemonic ?? result.inputMnemonic;
  await _afterIdentityEstablished(mnemonic, input.passphrase ?? '');
  return result;
}

/**
 * Restore an identity from a mnemonic (+ optional passphrase). Replaces the
 * record on this device; throws `InvalidMnemonicError` without persisting
 * when the phrase is bad.
 * @param {string} mnemonic
 * @param {string} [passphrase='']
 * @returns {Promise<object>} The status view.
 */
export async function restoreIdentity(mnemonic, passphrase = '') {
  const status = await userIdentity.restoreIdentity(mnemonic, passphrase);
  refreshUserIdentity();
  await _afterIdentityEstablished(mnemonic, passphrase);
  return status;
}

/** Whether a passkey is enrolled AND passkeys work here. */
export function hasPasskey() {
  return userIdentity.hasPasskey();
}

/**
 * Set up biometric unlock (WebAuthn PRF key-wrap of the mnemonic).
 * Throws `PasskeyUnavailableError` outside a secure context and
 * `IdentityBackendUnavailableError` until the crypto engine lands.
 * @returns {Promise<object>} The status view.
 */
export async function enrollPasskey() {
  const status = await userIdentity.enrollPasskey();
  refreshUserIdentity();
  return status;
}

/**
 * Unlock with the enrolled passkey. Same error classes as `enrollPasskey`,
 * plus a not-enrolled message.
 * @returns {Promise<object>} The status view.
 */
export async function unlockWithPasskey() {
  const status = await userIdentity.unlockWithPasskey();
  refreshUserIdentity();
  return status;
}

/**
 * Remove the enrolled passkey (the recovery phrase is unaffected).
 * @returns {Promise<object>} The status view.
 */
export async function removePasskey() {
  const status = await userIdentity.removePasskey();
  refreshUserIdentity();
  return status;
}

// ── Identity crypto backend (wasm → facade injection) ─────────

/**
 * Build the wasm-backed operations the identity facade needs and hand them to
 * `userIdentity.setIdentityBackend` after wasm init. The facade never imports
 * wasm; tests inject a mock instead.
 *
 * @param {object} wasm The loaded `cawala_client.js` module.
 */
function _wasmIdentityBackend(wasm) {
  const withIdentity = (mnemonic, passphrase, extract) => {
    const identity = wasm.UserIdentity.fromMnemonic(mnemonic, passphrase ?? '');
    try {
      return extract(identity);
    } finally {
      identity.free?.();
    }
  };
  return {
    deriveAddress: (mnemonic, passphrase) =>
      withIdentity(mnemonic, passphrase, (identity) => identity.address()),
    secretBytes: (mnemonic, passphrase) =>
      withIdentity(mnemonic, passphrase, (identity) => identity.secretBytes()),
    transportSeed: (mnemonic, passphrase) =>
      wasm.transportSeedFromMnemonic(mnemonic, passphrase ?? ''),
  };
}

/**
 * After an explicit create/restore: persist the mnemonic-derived transport
 * seed (so one phrase restores the NodeId) and push the derived secp256k1
 * secret into the live node (so V4 orders sign without a reload).
 *
 * @param {string|null} mnemonic The phrase the record was derived from.
 * @param {string} [passphrase='']
 */
async function _afterIdentityEstablished(mnemonic, passphrase = '') {
  await _persistDerivedTransportSeed(mnemonic, passphrase);
  // Fresh install: the running node was spawned with a random seed and its
  // live NodeId does not match the phrase yet. Re-spawn with the derived seed
  // NOW, before any join/registration can happen, so a same-session join's
  // ChildEntry/anchor is never orphaned by the next reload. A legacy stored
  // seed is preserved (never stale) so this is a no-op there.
  if (_transportIdentityIsStale()) {
    await _reactivateTransportIdentity();
  } else {
    _applyStoredUserIdentity(_clientNode);
  }
}

/**
 * Re-spawn the live client with the currently persisted (mnemonic-derived)
 * transport seed, replacing the fresh-install random-seed node. Keeps the
 * held identity Web Lock (it is never released/re-acquired mid-session),
 * clears any stale-seed registration bookkeeping, and leaves the node ready to
 * join under the mnemonic-derived NodeId.
 *
 * Best-effort: on failure the stale flag stays set and `requestJoin` refuses
 * until a reload, so a join can never occur on the wrong NodeId.
 *
 * @returns {Promise<boolean>} Whether the node now runs the derived seed.
 */
async function _reactivateTransportIdentity() {
  if (!_wasmModule) return false;
  const previous = _clientNode;
  _stopControlPoller();
  if (previous) {
    // Drop the in-memory user identity before freeing, then release the node.
    try {
      previous.clear_user_identity?.();
    } catch {
      /* ignore */
    }
    try {
      previous.free?.();
    } catch {
      /* ignore */
    }
    _clientNode = null;
  }
  _ethRegisteredFor = null;
  _ethRegistration = null;
  _lastControlEvent = null;
  _trustEstablished = false;
  try {
    await _spawnRealNode();
  } catch (err) {
    console.warn('[api] could not re-activate the mnemonic-derived transport identity', err);
    return false;
  }
  // Publish the new self endpoint id so the admin self-target keeps matching
  // the live node (App.svelte set it once at init).
  try {
    clientState.endpointId = _clientNode.endpoint_id();
  } catch {
    /* ignore */
  }
  return true;
}

/**
 * Whether the live node's transport seed differs from the currently persisted
 * one. True only in the fresh-install create/restore window (or if the re-spawn
 * failed): the persisted seed is now mnemonic-derived but the running node
 * still holds the random startup seed. Join/registration must not run while
 * this is true.
 *
 * @returns {boolean}
 */
function _transportIdentityIsStale() {
  if (_spawnedSeedHex == null) return false;
  const currentHex = _readStoredSeedHex();
  return currentHex != null && currentHex !== _spawnedSeedHex;
}

/**
 * Derive the deterministic Ed25519 transport seed from the mnemonic and store
 * it under `cawala.identity.v1` (hex). Only called at explicit create/restore,
 * and only when this install had **no stored seed** at boot (fresh install /
 * session-only): a stored legacy seed is never silently rekeyed, so pinned
 * nodeId-scoped data is not orphaned (Addendum C §6). The caller then
 * re-spawns the live node with the new seed (`_reactivateTransportIdentity`)
 * so the running NodeId matches the mnemonic before any join.
 *
 * @param {string|null} mnemonic
 * @param {string} [passphrase='']
 */
async function _persistDerivedTransportSeed(mnemonic, passphrase = '') {
  if (!mnemonic) return;
  if (_identitySource === 'stored') {
    // This install already had a transport seed (legacy random or a previous
    // derivation): preserve it. Only the ETH identity is adopted.
    return;
  }
  let seed;
  try {
    seed = await userIdentity.deriveTransportSeed(mnemonic, passphrase);
  } catch (err) {
    _warnOnce(
      'identity-transport-derive',
      '[api] could not derive the transport seed from the phrase',
      err,
    );
    return;
  }
  if (!(seed instanceof Uint8Array) || seed.length !== SEED_BYTES) {
    _warnOnce('identity-transport-len', '[api] derived transport seed has the wrong length; ignoring it');
    return;
  }
  _memorySeed = seed;
  try {
    window.localStorage.setItem(IDENTITY_KEY, _bytesToHex(seed));
    _identityPersistent = true;
  } catch (err) {
    _identityPersistent = false;
    _warnOnce(
      'identity-transport-write',
      '[api] could not persist the mnemonic-derived transport seed (private mode/quota)',
      err,
    );
  }
}

/**
 * Feed the persisted derived secp256k1 secret back into a node so it signs V4
 * orders and can register its anchor. No-op when the node or secret is absent.
 * Never throws.
 *
 * @param {object|null} node
 * @returns {boolean} Whether the identity was applied.
 */
function _applyStoredUserIdentity(node) {
  if (!node || typeof node.set_user_identity_from_secret !== 'function') return false;
  let secret;
  try {
    secret = userIdentity.getIdentitySecretBytes();
  } catch (err) {
    _warnOnce('user-identity-read', '[api] could not read the stored user identity secret', err);
    return false;
  }
  if (!secret) return false;
  try {
    node.set_user_identity_from_secret(secret);
    return true;
  } catch (err) {
    _warnOnce('user-identity-set', '[api] could not set the user identity from the stored secret', err);
    return false;
  }
}

// ── Internal state ────────────────────────────────────────────

let _useMock = true;
let _wasmModule = null;
let _clientNode = null;

// Identity/state storage keys. Classification of every key (which are
// authoritative-local, best-effort cache, or non-authoritative) lives in
// `storage.js`; these are the concrete key names that module documents.
// The identity seed stays global (one browser install == one identity). The
// state/ledger blobs are identity-scoped: `${STATE_KEY}:<nodeId>`. The
// un-suffixed keys are the legacy (pre-portability) locations and are read once
// as a backward-compat fallback on load.
const IDENTITY_KEY = STORAGE_KEYS.IDENTITY;
const STATE_KEY = STORAGE_KEYS.STATE;
// Distinct key for the secret-free ledger blob (balance/activity/pending).
const LEDGER_KEY = STORAGE_KEYS.LEDGER;
const SEED_BYTES = 32;

/**
 * Identity-scoped storage key: `cawala.state.v1:<nodeId>`.
 * @param {string} base
 * @param {string} nodeId
 * @returns {string}
 */
function _scopedKey(base, nodeId) {
  return `${base}:${nodeId}`;
}

// Keep the JS activity list bounded like Rust `MAX_ACTIVITY_ENTRIES`.
const MAX_ACTIVITY_ENTRIES = 200;

let _identityPersistent = false;
let _memorySeed = null; // in-session fallback when localStorage is unusable
// Where the active transport seed came from: 'stored' (a seed already on this
// install — legacy or previously derived: NEVER overwritten) or 'generated'
// (fresh install / session-only: a create/restore may replace it with the
// mnemonic-derived seed). Drives Addendum C §6 migration policy.
let _identitySource = 'memory';

// The transport seed hex the live node was actually spawned with. Compared
// against the persisted seed to detect the fresh-install create/restore window
// (running node still on the random startup seed while `cawala.identity.v1`
// now holds the mnemonic-derived one) so a stale NodeId can never be joined.
let _spawnedSeedHex = null;

// Control-event poller + last drained event.
let _controlPoller = null;
let _lastControlEvent = null;

// Whether the TOFU trust anchors (pinned_ledger / pinned_leaf_keys) were
// restored from a persisted ledger cache at boot. False on a fresh origin (no
// cache): trust is not established, and a later receipt must not be silently
// treated as TOFU-established. Set once in `_spawnRealNode`.
let _trustEstablished = false;

// ETH-anchor registration bookkeeping. `_ethRegisteredFor` keys the joined
// session (`<parent>:<address>`) so `register_eth_address()` is attempted once
// per join, not on every poller tick; reset on detach/teardown. The last
// outcome is exposed via `getEthRegistrationStatus()` for the UI.
let _ethRegisteredFor = null;
/** @type {{ status: string, address: string|null, trigger: string, at: number, error: string|null }|null} */
let _ethRegistration = null;

// JS-side in-flight payment map keyed by order hash hex, for UI status.
const _pendingSends = new Map();
// Throttle duplicate balance requests fired from init + spawnClient.
let _lastBalanceRequestAt = 0;
// Throttle the poller-driven balance pull so node-side (CLI) funding surfaces.
let _lastAutoBalanceRefreshAt = 0;
// visibilitychange handler ref, so the poller can add/remove it idempotently.
let _visibilityHandler = null;

// Best-effort multi-tab identity leadership.
let _lockRelease = null;
let _multiTabLeader = false;
let _multiTabWarning = null;

// Warn-once bookkeeping (avoid spamming the console every 2 s).
const _warned = new Set();
function _warnOnce(key, ...args) {
  if (_warned.has(key)) return;
  _warned.add(key);
  console.warn(...args);
}

/**
 * Whether we are running in mock mode.
 */
export function isMockMode() {
  return _useMock;
}

/**
 * Whether the stable identity seed is persisted in localStorage. Returns
 * false when storage is unavailable (Safari private mode / quota) and the
 * identity is currently session-only.
 */
export function isIdentityPersistent() {
  return _identityPersistent;
}

/**
 * Test-only seam: install a fake wasm client and switch the module into live
 * mode (`node != null`) without touching the network, wasm, or storage. Passing
 * `null` restores mock mode. Not used by the app; it exists so the live-call
 * boundary (e.g. the `bigint` amount) can be unit-tested on plain Node.
 * @param {object|null} node
 */
export function __setClientForTest(node) {
  _clientNode = node ?? null;
  _useMock = _clientNode == null;
}

/**
 * Test-only seam: drive the real boot path (`_spawnRealNode`) against an
 * injected fake wasm module — no wasm build, network, or Web Locks. Used to
 * exercise the fail-closed trust / pin-preservation boot behavior on plain
 * Node. Not used by the app; call the returned `stop()` so the control poller
 * and injected module do not outlive the test.
 *
 * Starts in mock mode exactly like `initApi`, so the boot path itself must flip
 * `_useMock` off once a live node exists. This keeps the seam faithful to the
 * runtime ordering: a regression that flips it too late (or a failed spawn)
 * leaves the module in mock mode and is observable to the test.
 * @param {object} wasm A fake module with `ClientNode.spawn_control` (and,
 *   when no identity is pre-seeded, `generate_secret_key`).
 * @returns {Promise<{ node: object, stop: () => void }>}
 */
export async function __bootRealNodeForTest(wasm) {
  _wasmModule = wasm;
  _useMock = true;
  let node;
  try {
    node = await _spawnRealNode();
  } catch (err) {
    _wasmModule = null;
    throw err;
  }
  // Keep `_wasmModule` installed until `stop()` so the in-session re-activation
  // path (`_reactivateTransportIdentity`) behaves exactly as at runtime. The
  // `stop()` below tears it down.
  return {
    node,
    stop() {
      _stopControlPoller();
      try {
        _clientNode?.free?.();
      } catch {
        /* ignore */
      }
      _clientNode = null;
      _releaseIdentityLock();
      _trustEstablished = false;
      _ethRegisteredFor = null;
      _ethRegistration = null;
      _identitySource = 'memory';
      _memorySeed = null;
      _spawnedSeedHex = null;
      _useMock = true;
      _wasmModule = null;
    },
  };
}

// ── Initialization ────────────────────────────────────────────

/**
 * Initialize the API layer.
 *
 * `?mock` forces mock mode. Otherwise this dynamically imports the wasm
 * client, restores/generates the stable identity, spawns the control node, and
 * flips `_useMock` off. On ANY failure it falls back to mock data.
 */
export async function initApi() {
  // The user identity is local storage state, readable in every mode: load it
  // before anything else so the identity UI has a status from the first render.
  refreshUserIdentity();

  // Check URL param for forced mock.
  const params = new URLSearchParams(window.location.search);
  if (params.has('mock')) {
    _useMock = true;
    return;
  }

  try {
    const wasm = await import('../wasm/cawala_client.js');
    await wasm.default();
    _wasmModule = wasm;
    // Hand the real crypto engine to the identity facade: address/secret
    // derivation and the mnemonic-derived transport seed.
    userIdentity.setIdentityBackend(_wasmIdentityBackend(wasm));

    // Best-effort single-leader guard: avoid binding two live endpoints with
    // the same endpoint id from concurrent tabs.
    const isLeader = await _acquireIdentityLock();
    if (!isLeader) {
      _useMock = true;
      return;
    }

    // `_spawnRealNode` flips `_useMock` off itself once a real node is live
    // (before its post-spawn syncs), so there is no live-order gap here.
    await _spawnRealNode();
  } catch (err) {
    console.warn('[api] wasm init failed, using mock data', err);
    _stopControlPoller();
    if (_clientNode) {
      try {
        _clientNode.free?.();
      } catch {
        /* ignore */
      }
      _clientNode = null;
    }
    _releaseIdentityLock();
    _useMock = true;
  }
}

// ── Identity, state & spawn helpers ───────────────────────────

/**
 * Restore the persisted 32-byte seed, or generate and persist a fresh one.
 * Falls back to an in-memory seed (with a visible warning flag) when storage
 * throws (Safari private mode / quota). The load path never derives from a
 * mnemonic and never rekeys: a stored seed (legacy pre-R3 random, or a
 * previously mnemonic-derived one) is preserved (Addendum C §6).
 * @param {object} wasm
 * @returns {Uint8Array}
 */
function _loadOrCreateIdentity(wasm) {
  let storedHex = null;
  try {
    storedHex = window.localStorage.getItem(IDENTITY_KEY);
  } catch (err) {
    _warnOnce('identity-read', '[api] localStorage unavailable for identity read; using session-only identity', err);
  }

  if (storedHex) {
    try {
      const bytes = _hexToBytes(storedHex);
      if (bytes.length === SEED_BYTES) {
        _identityPersistent = true;
        _identitySource = 'stored';
        return bytes;
      }
      _warnOnce('identity-len', '[api] stored identity has the wrong length; generating a new one');
    } catch (err) {
      _warnOnce('identity-malformed', '[api] stored identity is malformed; generating a new one', err);
    }
  }

  // Reuse the in-session fallback if we already generated one.
  if (_memorySeed) {
    _identitySource = 'generated';
    return _memorySeed;
  }

  const seed = wasm.generate_secret_key(); // may throw → initApi falls back to mock
  _memorySeed = seed;
  _identitySource = 'generated';

  try {
    window.localStorage.setItem(IDENTITY_KEY, _bytesToHex(seed));
    _identityPersistent = true;
  } catch (err) {
    _identityPersistent = false;
    _warnOnce('identity-write', '[api] could not persist identity (private mode/quota); identity is session-only', err);
  }
  return seed;
}

/**
 * Read a base64 blob from an identity-scoped key, falling back once to the
 * legacy un-namespaced key for installs predating identity portability.
 * Best-effort: a missing, unreadable, or corrupt blob reads as null.
 * @param {string} base
 * @param {string} nodeId
 * @param {string} warnKey
 * @returns {Uint8Array|null}
 */
function _loadScopedBlob(base, nodeId, warnKey) {
  return readScopedBlob(base, nodeId, {
    onWarn(kind, err) {
      if (kind === 'decode') {
        _warnOnce(`${warnKey}-decode`, `[api] persisted ${base} is malformed; ignoring it`, err);
      } else {
        _warnOnce(warnKey, `[api] localStorage unavailable for ${base} read`, err);
      }
    },
  });
}

/**
 * Persist a base64 blob under its identity-scoped key. Best-effort; never throws.
 * @param {string} base
 * @param {Uint8Array} bytes
 * @param {string} warnKey
 */
function _persistScopedBlob(base, bytes, warnKey) {
  if (!_clientNode) return;
  let nodeId;
  try {
    nodeId = _clientNode.endpoint_id();
  } catch (err) {
    _warnOnce(`${warnKey}-id`, `[api] could not read endpoint id for ${base}`, err);
    return;
  }
  try {
    window.localStorage.setItem(_scopedKey(base, nodeId), _bytesToBase64(bytes));
  } catch (err) {
    _warnOnce(warnKey, `[api] could not persist ${base} (private mode/quota)`, err);
  }
}

/**
 * Load the persisted postcard state blob, if any.
 * @param {string} nodeId
 * @returns {Uint8Array|null}
 */
function _loadState(nodeId) {
  return _loadScopedBlob(STATE_KEY, nodeId, 'state-read');
}

/**
 * Persist `node.export_state()` to localStorage. Best-effort; never throws.
 */
function _persistState() {
  if (!_clientNode) return;
  try {
    const bytes = _clientNode.export_state();
    _persistScopedBlob(STATE_KEY, bytes, 'state-write');
  } catch (err) {
    _warnOnce('state-write', '[api] could not persist client state (private mode/quota)', err);
  }
}

/**
 * Load the persisted secret-free ledger state blob, if any.
 * @param {string} nodeId
 * @returns {Uint8Array|null}
 */
function _loadLedgerState(nodeId) {
  return _loadScopedBlob(LEDGER_KEY, nodeId, 'ledger-read');
}

/**
 * Persist `node.export_ledger_state()` to localStorage. Best-effort; never throws.
 */
function _persistLedgerState() {
  if (!_clientNode) return;
  try {
    const bytes = _clientNode.export_ledger_state();
    _persistScopedBlob(LEDGER_KEY, bytes, 'ledger-write');
  } catch (err) {
    _warnOnce('ledger-write', '[api] could not persist ledger state (private mode/quota)', err);
  }
}

/**
 * Whether the live node currently holds at least one authoritative-local TOFU
 * anchor: a non-empty `pinned_ledger` or a non-empty `pinned_leaf_keys` set.
 * Both live only inside the `cawala.ledger.v1` blob, so a non-empty set *after*
 * a successful import means the blob actually carried a trust pin.
 * @param {object} node
 * @returns {boolean}
 */
function _hasRestoredAnchors(node) {
  if (!node) return false;
  try {
    const pinnedLedger = _readLedgerStatus(node).pinnedLedger;
    if (typeof pinnedLedger === 'string' && pinnedLedger.length > 0) return true;
  } catch (err) {
    _warnOnce('trust-anchor-ledger', '[api] could not read pinned_ledger after restore', err);
  }
  return _readPinnedLeafKeys(node).length > 0;
}

/**
 * Spawn the real control client, restore state, and start the event poller.
 * @returns {Promise<import('../wasm/cawala_client.js').ClientNode>}
 */
async function _spawnRealNode() {
  const seed = _loadOrCreateIdentity(_wasmModule);
  const node = await _wasmModule.ClientNode.spawn_control(seed);
  // Record only after the spawn succeeded: a thrown spawn must leave the
  // previous seed in place so a stale NodeId stays detectably stale.
  _spawnedSeedHex = _bytesToHex(seed);
  const nodeId = node.endpoint_id();

  // Boot is tolerant of a missing/corrupt cache: the state/ledger blobs are
  // best-effort (see `storage.js`). A missing or bad blob starts us from empty
  // local state instead of failing; balance/height are re-validated from the
  // node via `request_balance`/`ledger_status` below.
  const stateBytes = _loadState(nodeId);
  const ledgerBytes = _loadLedgerState(nodeId);
  const restoreResult = restoreBlobs(node, {
    stateBytes,
    ledgerBytes,
    onWarn(kind, err) {
      console.warn(
        `[api] import_${kind === 'state' ? 'state' : 'ledger_state'} failed; starting from a fresh local state`,
        err,
      );
    },
  });

  // Trust anchors (pinned_ledger / pinned_leaf_keys) live inside the ledger
  // blob. Trust is established ONLY when that blob actually imported AND at
  // least one anchor was restored from it. A corrupt or version-bumped blob
  // leaves `ledgerImported === false` (its `import_ledger_state` threw), so a
  // later receipt must never be silently treated as TOFU-established even
  // though the bytes were present. Fail-closed; see `getTrustState()`.
  _trustEstablished = restoreResult.ledgerImported && _hasRestoredAnchors(node);

  // Rebuild the UI activity list from the restored state (persisted value
  // notices + terminal settlement records) so past activity survives a reload.
  _rebuildActivityFromState(node);

  _clientNode = node;
  // A real node is now live and assigned: reflect that immediately, before the
  // post-spawn syncs below (store mirrors, balance pull, join-state sync, and
  // `_maybeRegisterEthAddress('boot')` at the end). Setting this only in
  // `initApi`'s caller (after this function returned) left the flag true during
  // those syncs, so they ran as no-ops on a real boot. A failed `spawn_control`
  // never reaches this line, so a mock/failed boot still leaves it true (and
  // `initApi`'s catch resets it on any later failure).
  _useMock = false;
  // Reload path: a persisted derived secp256k1 secret (never the mnemonic)
  // restores the user's ETH identity so V4 orders sign without an unlock. The
  // transport seed was already consumed by `_loadOrCreateIdentity` above.
  _applyStoredUserIdentity(node);
  _persistState();
  // Pin safety: never overwrite a ledger blob whose import failed. The blob
  // carries the authoritative-local TOFU anchors (pinned_ledger /
  // pinned_leaf_keys), which the node cannot re-supply. Re-exporting the now
  // empty in-memory ledger state would clobber the only trusted copy with no
  // recovery path, so preserve the original bytes when a blob was present but
  // unreadable. A fresh origin (no blob) and a successful import both persist.
  const hadLedgerBlob = Boolean(ledgerBytes && ledgerBytes.length > 0);
  if (!hadLedgerBlob || restoreResult.ledgerImported) {
    _persistLedgerState();
  } else {
    _warnOnce(
      'ledger-preserve',
      '[api] ledger blob failed to import; preserving the original bytes so the authoritative-local TOFU anchors are not destroyed',
    );
  }
  // Reflect any restored verified balance in the reactive store immediately.
  _syncLedgerStoreFromStatus();
  _startControlPoller();
  // Surface a restored/approved join address app-wide before verifying it.
  _syncJoinStateIntoStore();
  // Derive the initial attachment status now that the address is known.
  _syncConnectionStatusIntoStore();
  // Publish which node this console is administering (persisted selection).
  _syncAdministeredNode();
  // (Re)verify the persisted balance as soon as an address is known.
  _requestBalanceIfJoined();
  // Already joined on load + an identity exists → register the ETH anchor
  // (quietly; `getEthRegistrationStatus()` carries the outcome).
  void _maybeRegisterEthAddress('boot');
  return node;
}

/**
 * Require a live client node, throwing a clear error if it is missing.
 */
function _requireNode() {
  if (!_clientNode) {
    throw new Error('Client is not initialized. Call initApi() before this operation.');
  }
  return _clientNode;
}

// ── Admin target (the ancestor admin mode points at) ──────────

/**
 * This browser's own kind. The web client is always a user leaf, so its kind is
 * known directly rather than inferred from a local child list it never has
 * (inference over an empty child list is `unknown`). Session-only.
 */
let _selfKind = NODE_KIND.USER;

/**
 * The ancestor chain this browser may administer, cached from the wasm walk.
 * `depth` 1 is the direct parent, the last entry is the root. Empty until
 * admin mode is unlocked and `discoverAdminTargets()` has run.
 * @type {Array<{ node: string, address: string|null, depth: number }>}
 */
let _adminTargets = [];

/**
 * The selected depth in that chain (null = fall back to the closest parent).
 * Reset to null when admin mode is locked.
 * @type {number|null}
 */
let _targetDepth = null;

/**
 * Last observed state per admin target (node id → probe), written only by
 * `probeAdminNode` / query outcomes. Never guessed, never persisted.
 * @type {Map<string, { status: string, kind: string|null, address: string|null, childrenCount: number|null, at: number }>}
 */
const _targetProbe = new Map();

/**
 * The selected ancestor, or null while admin mode is locked / undiscovered.
 * @returns {{ node: string, address: string|null, depth: number }|null}
 */
function _selectedTarget() {
  if (!adminLock.unlocked || _adminTargets.length === 0) return null;
  const wanted = _targetDepth ?? 1;
  return _adminTargets.find((target) => target.depth === wanted) ?? _adminTargets[0] ?? null;
}

/**
 * Resolve the target of an admin call: an explicit id, else the selected
 * ancestor, else `self` (this browser's own node).
 * @param {string} [nodeId]
 * @returns {string}
 */
function _normalizeTarget(nodeId) {
  if (nodeId != null) return String(nodeId).toLowerCase();
  const selected = _selectedTarget();
  return selected ? String(selected.node).toLowerCase() : SELF;
}

/**
 * Derive the admin-target view + capability flags for the current selection.
 * Pure read: never probes the network and never invents a kind or address.
 * @returns {{ view: object, caps: object }}
 */
function _deriveAdminView() {
  const mock = _useMock;
  const target = _normalizeTarget();
  const isSelf = target === SELF;
  const isMockNode = target === MOCK_NODE_ID;
  const selected = _selectedTarget();
  const probe = isSelf ? null : _targetProbe.get(target) ?? null;

  let status;
  if (mock) status = 'mock';
  else if (isSelf) status = 'self';
  else status = probe?.status ?? 'unknown';

  const kind = isMockNode
    ? inferNodeKind(MOCK_DATA.children)
    : isSelf
      ? _selfKind
      : probe?.kind ?? NODE_KIND.UNKNOWN;

  const address = isMockNode
    ? '0.3'
    : isSelf
      ? clientState.address ?? null
      : probe?.address ?? selected?.address ?? null;

  const unlocked = adminLock.unlocked;
  const canQuery = true; // self reads are local; admin reads degrade to []
  const canAdminister = unlocked && !isSelf;

  return {
    view: {
      nodeId: target,
      isSelf,
      label: isMockNode ? 'Mock node' : isSelf ? 'This browser' : null,
      depth: isSelf ? null : selected?.depth ?? null,
      kind,
      status,
      address,
      lastSeenAt: probe?.at ?? null,
      childrenCount: probe?.childrenCount ?? null,
      mock,
    },
    caps: {
      mock,
      canQueryNode: canQuery,
      canAdminister,
      canAdmin: canAdminister,
      unlocked,
    },
  };
}

/**
 * Push the current admin target into the reactive store (and capabilities).
 */
function _syncAdministeredNode() {
  const { view, caps } = _deriveAdminView();

  // A target change retargets every query: drop the previous target's rows
  // and tell the pages to refetch (targetEpoch) before publishing the view.
  const previous = administeredNode.nodeId;
  if (previous != null && previous !== view.nodeId) {
    resetDataState();
    bumpTargetEpoch();
  }

  applyAdministeredNode(view);
  applyAdminCapabilities({
    mock: caps.mock,
    canQueryNode: caps.canQueryNode,
    canAdminister: caps.canAdminister,
    unlocked: caps.unlocked,
  });
  Object.assign(apiCapabilities, _capabilityView(caps));
}

/**
 * The `getCapabilities()`-shaped view of the derived capability flags.
 * @param {object} caps
 */
function _capabilityView(caps) {
  return {
    mock: caps.mock,
    canAdmin: caps.canAdmin,
    canQueryPeers: false,
    canQueryNode: caps.canQueryNode,
    identityPersistent: _identityPersistent,
    multiTabLeader: _multiTabLeader,
    multiTabWarning: _multiTabWarning,
  };
}

/**
 * The current admin-target view (seed-free).
 * @returns {object}
 */
export function getAdministeredNode() {
  return _deriveAdminView().view;
}

/**
 * The ancestor chain admin mode can point at (seed-free, from the cache).
 * Empty while admin mode is locked.
 *
 * @returns {Array<{ node: string, address: string|null, depth: number }>}
 */
export function getAdminTargets() {
  if (!adminLock.unlocked) return [];
  return _adminTargets.map((target) => ({ ...target }));
}

/**
 * Refresh the ancestor chain: a live walk (`discover_admin_targets`), or the
 * synthetic two-level chain in mock mode. The selection is clamped to the new
 * chain, so a target that disappeared drops the console back to its parent.
 *
 * @returns {Promise<Array<{ node: string, address: string|null, depth: number }>>}
 */
export async function discoverAdminTargets() {
  let next = [];

  if (_useMock) {
    await mockDelay(200);
    // Mock is a data source, not a layout: two ancestors so the up/down
    // control has both an enabled and a disabled end to exercise. The walk is
    // complete, so the synthetic chain reaches the root.
    next = [
      { node: MOCK_NODE_ID, address: '0.3', depth: 1, isRoot: false },
      { node: `${MOCK_NODE_ID}-root`, address: '0', depth: 2, isRoot: true },
    ];
  } else {
    const node = _requireNode();
    const dtos = await node.discover_admin_targets();
    try {
      for (const dto of dtos) {
        next.push({
          node: String(dto.node),
          address: dto.address ?? null,
          depth: Number(dto.depth),
          // The walk stops at the first undesignated hop; only the node that
          // actually had no parent is the root.
          isRoot: Boolean(dto.is_root),
        });
      }
    } finally {
      for (const dto of dtos) dto.free?.();
    }
    next.sort((a, b) => a.depth - b.depth);
  }

  _adminTargets = next;
  const depths = _adminTargets.map((target) => target.depth);
  if (_targetDepth != null && !depths.includes(_targetDepth)) _targetDepth = null;
  if (_targetDepth == null && depths.length > 0) _targetDepth = depths[0];
  // Forget probes for ancestors that are no longer in the chain.
  for (const key of _targetProbe.keys()) {
    if (!_adminTargets.some((target) => target.node.toLowerCase() === key)) {
      _targetProbe.delete(key);
    }
  }
  _syncAdministeredNode();
  return getAdminTargets();
}

/**
 * Select an ancestor by depth (clamped to the chain). A change retargets every
 * admin query through `_syncAdministeredNode` (which bumps `targetEpoch`).
 *
 * @param {number} depth 1-based depth above this browser (1 = direct parent)
 * @returns {{ node: string, address: string|null, depth: number }|null}
 */
export function setAdministeredNode(depth) {
  if (!adminLock.unlocked || _adminTargets.length === 0) return null;
  const wanted = Number(depth);
  const hit = _adminTargets.find((target) => target.depth === wanted);
  if (!hit) return null;
  _targetDepth = hit.depth;
  _syncAdministeredNode();
  return { ...hit };
}

/**
 * Step one ancestor up (`delta` +1, toward the root) or down (-1, toward this
 * browser). Disabled at both ends of the chain; returns null there.
 *
 * @param {number} delta
 * @returns {{ node: string, address: string|null, depth: number }|null}
 */
export function stepAdminTarget(delta) {
  if (!adminLock.unlocked || _adminTargets.length === 0) return null;
  const current = _selectedTarget();
  if (!current) return null;
  return setAdministeredNode(current.depth + Number(delta));
}

/**
 * Bounds the up/down control needs to disable itself: null while locked.
 * @returns {{ current: number|null, min: number, max: number, count: number }|null}
 */
export function adminTargetBounds() {
  if (!adminLock.unlocked || _adminTargets.length === 0) return null;
  const depths = _adminTargets.map((target) => target.depth).sort((a, b) => a - b);
  const current = _selectedTarget()?.depth ?? null;
  return { current, min: depths[0], max: depths[depths.length - 1], count: depths.length };
}

/**
 * The policy document the unlock gate renders, its hash, and whatever this
 * browser acknowledged before (which is stale — and therefore called out —
 * when the document has changed since).
 *
 * @returns {{ text: string, hash: string, acknowledgedHash: string|null, acknowledgedAt: number|null, acknowledgementCurrent: boolean }}
 */
export function adminPolicyInfo() {
  const stored = readAcknowledgedPolicy();
  return {
    text: POLICY_TEXT,
    hash: POLICY_HASH,
    acknowledgedHash: stored?.hash ?? null,
    acknowledgedAt: stored?.at ?? null,
    acknowledgementCurrent: Boolean(stored && stored.hash === POLICY_HASH),
  };
}

/**
 * Unlock admin mode: record the policy acknowledgement (so a later edit to
 * `ADMIN_POLICY.md` invalidates it) and discover the ancestor chain. The
 * unlocked flag itself is memory only — a reload lands back on the gate.
 *
 * @returns {Promise<{ targets: Array<object>, acknowledgementCurrent: boolean }>}
 */
export async function unlockAdmin() {
  const stored = readAcknowledgedPolicy();
  const acknowledgementCurrent = Boolean(stored && stored.hash === POLICY_HASH);
  writeAcknowledgedPolicy(POLICY_HASH);
  applyAdminLock({
    unlocked: true,
    policyHash: POLICY_HASH,
    acknowledgedHash: POLICY_HASH,
    acknowledgedAt: Date.now(),
  });
  // Discovery failure must not undo the unlock: the Admin page can retry the
  // walk from its own control, and the acknowledgement is already recorded.
  let targets = [];
  try {
    targets = await discoverAdminTargets();
  } catch (err) {
    _warnOnce('admin-discover', '[api] ancestor discovery failed', err);
  }
  return { targets, acknowledgementCurrent };
}

/**
 * Lock admin mode: hide the admin surfaces, drop the discovered ancestor
 * chain, forget every observed target state, and clear the rows that were
 * fetched for an ancestor. The policy acknowledgement is kept so the gate can
 * still say whether the document changed since it was read.
 */
export function lockAdminMode() {
  applyAdminLock({ unlocked: false });
  _adminTargets = [];
  _targetDepth = null;
  _targetProbe.clear();
  resetDataState();
  _syncAdministeredNode();
}

/**
 * Record what a probe/query saw about an admin target (status/kind/address)
 * and refresh the stored view. Failures mark the target unreachable rather
 * than dropping the last observed kind.
 *
 * @param {string} target
 * @param {{ ok: boolean, kind?: string|null, address?: string|null, childrenCount?: number|null }} outcome
 */
function _recordTargetProbe(target, outcome) {
  const key = String(target).toLowerCase();
  const previous = _targetProbe.get(key);
  if (outcome.ok) {
    _targetProbe.set(key, {
      status: 'active',
      kind: outcome.kind ?? previous?.kind ?? null,
      address: outcome.address ?? previous?.address ?? null,
      childrenCount: outcome.childrenCount ?? previous?.childrenCount ?? null,
      at: Date.now(),
    });
  } else {
    _targetProbe.set(key, {
      status: 'unreachable',
      kind: previous?.kind ?? null,
      address: previous?.address ?? null,
      childrenCount: previous?.childrenCount ?? null,
      at: Date.now(),
    });
  }
  _syncAdministeredNode();
}

/**
 * Probe the current admin target: one `AdminQuery` (or a local snapshot read
 * for this browser's own node) that establishes reachability, kind and
 * address. Records what it saw so the context bar can show it; never throws.
 *
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<{ nodeId: string, ok: boolean, kind: string, address: string|null, childrenCount: number|null, pendingCount: number|null, error: string|null }>}
 */
export async function probeAdminNode(nodeId = undefined) {
  const target = _normalizeTarget(nodeId);

  if (_useMock) {
    const children = MOCK_DATA.children;
    const view = {
      nodeId: target,
      ok: true,
      kind: target === SELF ? NODE_KIND.USER : inferNodeKind(children),
      address: target === SELF ? clientState.address ?? null : '0.3',
      childrenCount: children.length,
      pendingCount: MOCK_DATA.joinRequests.length,
      error: null,
    };
    if (target === SELF) {
      _selfKind = view.kind;
      _syncAdministeredNode();
    } else {
      _recordTargetProbe(target, {
        ok: true,
        kind: view.kind,
        address: view.address,
        childrenCount: view.childrenCount,
      });
    }
    return view;
  }

  if (target === SELF) {
    // Our own topology is local state: no network round-trip.
    try {
      const rows = _readLocalChildren();
      // The browser client is always a user leaf: its kind is known directly,
      // not inferred from its children (a user leaf has none).
      _selfKind = NODE_KIND.USER;
      _syncAdministeredNode();
      return {
        nodeId: target,
        ok: true,
        kind: _selfKind,
        address: clientState.address ?? null,
        childrenCount: rows.length,
        pendingCount: null,
        error: null,
      };
    } catch (err) {
      return { nodeId: target, ok: false, kind: NODE_KIND.UNKNOWN, address: null, childrenCount: null, pendingCount: null, error: _errorMessage(err) };
    }
  }

  try {
    const data = await _queryAdminSnapshot(target);
    const kind = inferNodeKind(data.children);
    const address =
      data.address ?? _adminTargets.find((t) => t.node.toLowerCase() === target)?.address ?? null;
    _recordTargetProbe(target, {
      ok: true,
      kind,
      address,
      childrenCount: data.children.length,
    });
    return {
      nodeId: target,
      ok: true,
      kind,
      address,
      childrenCount: data.children.length,
      pendingCount: data.pending,
      error: null,
    };
  } catch (err) {
    _recordTargetProbe(target, { ok: false });
    return {
      nodeId: target,
      ok: false,
      kind: NODE_KIND.UNKNOWN,
      address: null,
      childrenCount: null,
      pendingCount: null,
      error: _errorMessage(err),
    };
  }
}

/**
 * Map one `ChildDto` to a plain row. Liveness is never part of a snapshot
 * read, so `online` stays null ("Unknown") instead of guessing offline.
 * @param {object} child
 */
function _mapChild(child) {
  return {
    address: child.address ?? null,
    endpointId: child.child_id,
    balance: null,
    seniority: child.date_joined ? new Date(child.date_joined * 1000).toISOString() : null,
    online: null,
    slot: child.slot,
    kind: child.kind ?? null,
  };
}

/**
 * Read this client's own children from the local topology snapshot (no
 * network round-trip).
 * @returns {Array<object>}
 */
function _readLocalChildren() {
  const snap = _requireNode().local_snapshot();
  const children = snap.children;
  try {
    return children.map(_mapChild);
  } finally {
    for (const child of children) child.free?.();
    snap.free?.();
  }
}

/**
 * Run one `AdminQuery` against `target`, then copy the reply to plain data
 * (freeing every handle it created). The wasm client resolves ancestor
 * addresses itself — there is no `node_addr` argument and no key to install.
 *
 * @param {string} target
 * @returns {Promise<{ nodeId: string|null, address: string|null, admins: Array<string>, children: Array<object>, pending: number, pendingRows: Array<object> }>}
 */
async function _queryAdminSnapshot(target) {
  // Admin mode is a client-side gate: while locked, ancestor state is hidden
  // rather than fetched (self is always readable — it is local state).
  if (target !== SELF && target !== clientState.endpointId && !adminLock.unlocked) {
    throw new AdminUnavailableError('admin query (admin mode is locked)');
  }
  const node = _requireNode();
  const snapshot = await node.admin_query(target);
  return _readAdminSnapshot(snapshot);
}

/**
 * Copy an `AdminSnapshotDto` to plain data and free every wasm handle it
 * created (children, pending rows, the topology sub-snapshot, the snapshot).
 * Handles are read once and freed once: wasm-bindgen getters hand back a fresh
 * wrapper per access, so a second read would double-free.
 *
 * @param {object} snapshot
 * @returns {{ nodeId: string|null, address: string|null, admins: Array<string>, children: Array<object>, pending: number, pendingRows: Array<object> }}
 */
function _readAdminSnapshot(snapshot) {
  let topo = null;
  let children = [];
  let rows = [];
  try {
    topo = snapshot.node;
    children = topo.children;
    rows = snapshot.pending ?? [];
    return {
      nodeId: topo.node_id ?? null,
      address: topo.address ?? null,
      // Designated administrator child ids (strings; no handles to free).
      admins: [...(snapshot.admins ?? [])],
      children: children.map(_mapChild),
      pending: rows.length,
      pendingRows: rows.map((row) => ({
        endpointId: row.child_id,
        slot: row.desired_slot ?? null,
        kind: row.kind ?? null,
        operator: row.operator ?? null,
        expiry: row.expiry ?? null,
      })),
    };
  } finally {
    for (const child of children) child.free?.();
    for (const row of rows) row.free?.();
    topo?.free?.();
    snapshot.free?.();
  }
}

/**
 * Take the exclusive `cawala-identity` lock as the session leader.
 * Returns true when leadership is held (or Web Locks is unsupported), false
 * when another tab already owns the identity.
 * @returns {Promise<boolean>}
 */
async function _acquireIdentityLock() {
  if (
    typeof navigator === 'undefined' ||
    !navigator.locks ||
    typeof navigator.locks.request !== 'function'
  ) {
    return true; // No Web Locks: best effort, assume leader.
  }

  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };

    navigator.locks
      .request('cawala-identity', { mode: 'exclusive', ifAvailable: true }, (lock) => {
        if (!lock) {
          _multiTabWarning =
            'Another Cawala tab already owns this identity; running in mock mode to avoid duplicating the live endpoint.';
          console.warn('[api] multi-tab: identity lock held elsewhere; using mock data');
          done(false);
          return undefined;
        }
        _multiTabLeader = true;
        done(true);
        // Hold the exclusive lock for the lifetime of this client so a second
        // tab cannot bind another live endpoint with the same id.
        return new Promise((release) => {
          _lockRelease = release;
        });
      })
      .catch((err) => {
        _multiTabWarning = `Identity lock unavailable: ${err?.message ?? String(err)}`;
        console.warn('[api] multi-tab: identity lock request failed; continuing without lock', err);
        done(true);
      });
  });
}

/**
 * Release the held identity lock, if any.
 */
function _releaseIdentityLock() {
  if (_lockRelease) {
    const release = _lockRelease;
    _lockRelease = null;
    try {
      release();
    } catch {
      /* ignore */
    }
  }
}

// ── Control-event poller ──────────────────────────────────────

/**
 * Mirror the live join address into `clientState` so an approval accepted
 * outside the join page propagates app-wide within one poller tick. No-op in
 * mock mode; never throws.
 */
function _syncJoinStateIntoStore() {
  if (_useMock || !_clientNode) return;
  let status;
  try {
    status = _readJoinStatus(_clientNode);
  } catch (err) {
    _warnOnce('join-state-sync', '[api] join status read failed', err);
    return;
  }
  const address = status.address ?? null;
  if (address !== clientState.address) {
    clientState.address = address;
  }
}

/**
 * Derive the parent-attachment connection status from the authoritative
 * signals. Single source of truth for both the reactive store
 * (`_syncConnectionStatusIntoStore`) and `getConnectionStatus()`.
 *
 * The indicator means "attached to a parent node", not merely "a wasm client
 * exists":
 *   - mock                                   → CONNECTION.MOCK
 *   - live, no client                        → CONNECTION.DISCONNECTED
 *   - live, join pending / awaiting approval → CONNECTION.CONNECTING
 *   - live, no address (none/rejected)       → CONNECTION.DISCONNECTED
 *   - live, joined + parent reachable        → CONNECTION.CONNECTED
 *   - live, joined + parent unreachable      → CONNECTION.DISCONNECTED
 *
 * `parentStatus()` is passive/informational and MUST never gate an action.
 *
 * @returns {string} One of CONNECTION.*
 */
function _deriveConnectionStatus() {
  if (_useMock) return CONNECTION.MOCK;
  if (!_clientNode) return CONNECTION.DISCONNECTED;

  let joinState = JOIN_STATE.NONE;
  try {
    joinState = getJoinStatus().state;
  } catch (err) {
    _warnOnce('connection-join-status', '[api] join status read failed', err);
  }
  // Awaiting approval: amber "Connecting…" even before an address exists.
  if (joinState === JOIN_STATE.PENDING) return CONNECTION.CONNECTING;
  // Not joined (state none/rejected) or detached: no parent to be attached to.
  if (clientState.address == null) return CONNECTION.DISCONNECTED;

  // Joined: the only green state is a reachable parent. A failed probe is red.
  let reachable = true;
  try {
    reachable = parentStatus().reachable;
  } catch (err) {
    _warnOnce('connection-parent-status', '[api] parent status read failed', err);
  }
  return reachable ? CONNECTION.CONNECTED : CONNECTION.DISCONNECTED;
}

/**
 * Mirror the derived parent-attachment status into `clientState` so the
 * indicator stays current app-wide. Idempotent; only writes on change.
 */
function _syncConnectionStatusIntoStore() {
  const next = _deriveConnectionStatus();
  if (next !== clientState.connectionStatus) {
    clientState.connectionStatus = next;
  }
}

/**
 * Re-query the balance when the tab becomes visible again. Still subject to
 * the 1 s throttle in `_requestBalanceIfJoined`.
 */
function _onVisibilityChange() {
  if (typeof document === 'undefined' || document.visibilityState === 'hidden') return;
  if (_useMock || !_clientNode || clientState.address == null) return;
  _requestBalanceIfJoined();
}

/**
 * Start the 2 s control-event drain loop (idempotent).
 */
function _startControlPoller() {
  if (_controlPoller != null) return;
  _controlPoller = setInterval(() => {
    _syncJoinStateIntoStore();
    _drainControlEvents();
    _drainLedgerEvents();
    // Derive parent attachment after the drains so an approval/detach processed
    // in this tick (which may set/clear `clientState.address`) is reflected.
    _syncConnectionStatusIntoStore();
    // Periodic pull so a node-side (CLI) funding is picked up without a reload.
    if (
      clientState.address != null &&
      !(typeof document !== 'undefined' && document.visibilityState === 'hidden')
    ) {
      const now = Date.now();
      if (now - _lastAutoBalanceRefreshAt >= 20000) {
        _lastAutoBalanceRefreshAt = now;
        _requestBalanceIfJoined();
      }
    }
  }, 2000);
  if (typeof document !== 'undefined' && _visibilityHandler == null) {
    _visibilityHandler = _onVisibilityChange;
    document.addEventListener('visibilitychange', _visibilityHandler);
  }
}

/**
 * Stop the control-event drain loop.
 */
function _stopControlPoller() {
  if (_controlPoller != null) {
    clearInterval(_controlPoller);
    _controlPoller = null;
  }
  if (typeof document !== 'undefined' && _visibilityHandler != null) {
    document.removeEventListener('visibilitychange', _visibilityHandler);
    _visibilityHandler = null;
  }
}

/**
 * Drain all queued control events into `_lastControlEvent`, copying each DTO to
 * a plain object and freeing it. Kinds are `accepted`, `rejected`, and
 * `detached`; a `detached` event also clears the mirrored join address.
 * On `accepted`/`detached` the wasm ledger was re-pinned/cleared synchronously:
 * persist the ledger blob before the state blob, resync the reactive ledger
 * store, and drop any stale `ledger_key_mismatch` error. Persists state when
 * anything was drained.
 */
function _drainControlEvents() {
  if (_useMock || !_clientNode) return;
  let drained = false;
  let accepted = false;
  let parentChanged = false;
  try {
    for (;;) {
      const ev = _clientNode.try_recv_control_event();
      if (!ev) break;
      _lastControlEvent = {
        kind: ev.kind,
        parent: ev.parent,
        slot: ev.slot ?? null,
        address: ev.address ?? null,
        dateJoined: ev.date_joined ?? null,
        reason: ev.reason ?? null,
      };
      if (_lastControlEvent.kind === CONTROL_EVENT.ACCEPTED) {
        accepted = true;
        parentChanged = true;
      }
      if (_lastControlEvent.kind === CONTROL_EVENT.DETACHED) {
        // The wasm state is parentless now; clear the mirrored address so the
        // UI drops out of the joined view ("Left network") immediately.
        clientState.address = null;
        parentChanged = true;
        // A later re-join must register the ETH anchor again.
        _ethRegisteredFor = null;
      }
      ev.free?.();
      drained = true;
    }
  } catch (err) {
    _warnOnce('control-drain', '[api] control event drain failed', err);
    return;
  }
  if (parentChanged) {
    // The parent-scoped ledger binding changed in wasm: a prior mismatch no
    // longer describes the current leaf. Persist the ledger blob before the
    // state blob so a reload cannot restore the stale pin.
    ledgerState.error = null;
    _persistLedgerState();
    _syncLedgerStoreFromStatus();
  }
  if (drained) _persistState();
  // A fresh approval means an address now exists: verify its balance.
  if (accepted) {
    _requestBalanceIfJoined();
    // Now joined: register the user's ETH anchor with the parent (once).
    void _maybeRegisterEthAddress('join');
  }
}

/**
 * The most recently drained control event, as a plain object (or null).
 */
export function getLastControlEvent() {
  return _lastControlEvent ? { ..._lastControlEvent } : null;
}

// ── ETH anchor registration (control variant 24) ──────────────

/**
 * The last `register_eth_address()` outcome, or null. `status` is the wasm
 * reply bucket (`accepted` / `rejected:<code>` / `unexpected`) or `error` for
 * a transport/JS failure; `trigger` is `boot` or `join`.
 *
 * NOTE (structure scan): no component reads this today. The join-time outcome
 * is surfaced by `_surfaceEthRegistration`'s toast; this getter exists so a
 * future surface can show the (silent) boot-time outcome without another
 * plumbing pass. A component consumer is the only missing piece.
 *
 * @returns {object|null}
 */
export function getEthRegistrationStatus() {
  return _ethRegistration ? { ..._ethRegistration } : null;
}

/**
 * Register this leaf's ETH anchor with its direct parent (once per joined
 * session), when a joined client has a user identity set. Idempotent: keyed by
 * the parent + assigned address, so the 2 s poller cannot spam the parent.
 *
 * Surfaces the outcome as a concise toast on a fresh join (accepted/rejected);
 * on boot the outcome is only recorded (no toast) so a reload is not noisy.
 * A transport failure clears the guard so a later tick can retry.
 *
 * @param {'boot'|'join'} trigger
 */
async function _maybeRegisterEthAddress(trigger) {
  const node = _clientNode;
  if (_useMock || !node) return;
  if (typeof node.register_eth_address !== 'function') return;
  // A stale NodeId must not register the ETH anchor: the parent would record
  // it against the random startup leaf and orphan it on the next reload.
  if (_transportIdentityIsStale()) return;

  let join = null;
  try {
    join = _readJoinStatus(node);
  } catch (err) {
    _warnOnce('eth-register-join', '[api] could not read join status before ETH registration', err);
    return;
  }
  if (!join?.address) return; // not joined yet

  let ethAddress = null;
  try {
    ethAddress = node.user_eth_address?.() ?? null;
  } catch (err) {
    _warnOnce('eth-register-identity', '[api] could not read the user ETH address', err);
    return;
  }
  if (!ethAddress) return; // no user identity set on this node

  const key = `${join.parent ?? ''}:${join.address}`;
  if (_ethRegisteredFor === key) return;
  _ethRegisteredFor = key;

  try {
    const bucket = await node.register_eth_address();
    _ethRegistration = {
      status: String(bucket ?? 'unexpected'),
      address: ethAddress,
      trigger,
      at: Date.now(),
      error: null,
    };
    _surfaceEthRegistration(_ethRegistration);
  } catch (err) {
    // Missing join/identity or an unreachable parent: not fatal — the identity
    // still signs; allow a later join/poller tick to retry.
    _ethRegisteredFor = null;
    _ethRegistration = {
      status: 'error',
      address: ethAddress,
      trigger,
      at: Date.now(),
      error: err?.message || String(err),
    };
    _warnOnce('eth-register', '[api] ETH address registration failed', err);
  }
}

/**
 * Surface an ETH-registration outcome once, on a fresh join. Boot-time
 * registration stays silent (recorded via `getEthRegistrationStatus()`).
 * @param {{ status: string, address: string|null, trigger: string }} outcome
 */
function _surfaceEthRegistration(outcome) {
  if (outcome.trigger !== 'join') return;
  const status = outcome.status;
  if (status === 'accepted') {
    showToast('Account address registered with the network.', 'ok');
  } else if (status.startsWith('rejected')) {
    const code = status.includes(':') ? status.slice(status.indexOf(':') + 1) : '';
    showToast(
      code
        ? `The network did not accept your account address (${code}).`
        : 'The network did not accept your account address.',
      'warn',
      6000,
    );
  } else {
    showToast('Account address registration returned an unexpected reply.', 'warn', 6000);
  }
}

// ── Ledger-event poller ───────────────────────────────────────

/**
 * Drain all queued ledger events into `ledgerState`, copying each DTO to a
 * plain object and freeing it.
 *
 * After draining, the authoritative balance/height/pinned-ledger/pending
 * counts are resynced from `ledger_status()` and the ledger blob is persisted
 * whenever anything was drained. An `invalid` event never mutates the verified
 * balance; it only sets `ledgerState.error`.
 */
function _drainLedgerEvents() {
  if (_useMock || !_clientNode) return;
  let drained = false;
  try {
    for (;;) {
      const ev = _clientNode.try_recv_ledger_event();
      if (!ev) break;
      let plain;
      try {
        plain = {
          kind: ev.kind,
          orderHash: ev.order_hash ?? null,
          status: ev.status ?? null,
          reason: ev.reason ?? null,
          amount: ev.amount ?? null,
          balance: ev.balance ?? null,
          height: ev.height ?? null,
          counterparty: ev.counterparty ?? null,
          entrySeq: ev.entry_seq ?? null,
          failedAt: ev.failed_at ?? null,
        };
      } finally {
        ev.free?.();
      }
      _applyLedgerEvent(plain);
      drained = true;
    }
  } catch (err) {
    _warnOnce('ledger-drain', '[api] ledger event drain failed', err);
    return;
  }
  _syncLedgerStoreFromStatus();
  // Reflect any newly persisted movements/settlements in the UI activity list.
  _rebuildActivityFromState();
  if (drained) _persistLedgerState();
}

/**
 * Fold one plain ledger-event object into `ledgerState`, resolving a matching
 * in-flight send by order hash.
 * @param {object} plain
 */
function _applyLedgerEvent(plain) {
  if (!plain || typeof plain.kind !== 'string') return;

  if (plain.kind === LEDGER_EVENT.ORDER_RESULT) {
    const orderHash = plain.orderHash;
    const status = plain.status ?? null;
    const isVerifiedSuccess =
      status === ORDER_STATUS.APPLIED || status === ORDER_STATUS.DUPLICATE;

    if (orderHash) {
      const pending = _pendingSends.get(orderHash);
      if (pending) {
        if (status) pending.status = status;
        pending.reason = plain.reason ?? pending.reason;
        pending.failedAt = plain.failedAt ?? pending.failedAt;
        pending.resolvedAt = Date.now();
      }
    }
    // Record a UI transfer entry only for a cryptographically verified
    // terminal order. The DTO exposes the order hash (not the ledger entry
    // hash), so that is the stable id. `unverified` is never success.
    if (isVerifiedSuccess) {
      _recordActivity({
        id: orderHash ?? `seq-${plain.entrySeq ?? Date.now()}`,
        type: ACTIVITY_TYPES.TRANSFER,
        from: getAddress(),
        to: plain.counterparty ?? null,
        amount: plain.amount ?? null,
        signedBy: _parentNodeId(),
        timestamp: new Date().toISOString(),
        // Carry the ledger seq so `_rebuildActivityFromState` can collapse this
        // live movement with the same movement restored from persisted state.
        ...(plain.entrySeq != null ? { entrySeq: plain.entrySeq } : {}),
      });
    }
    if (typeof plain.balance === 'number') {
      ledgerState.balance = plain.balance;
      ledgerState.verifiedAt = Date.now();
    }
    if (typeof plain.height === 'number') {
      ledgerState.height = plain.height;
    }
    // An unverified settlement is terminal but NOT success: keep a clear
    // notice and never clear the error as if the transfer had applied.
    if (status === ORDER_STATUS.UNVERIFIED) {
      const reason = plain.reason ?? 'settlement proof could not be verified';
      const where = orderHash ? ` for order ${orderHash}` : '';
      ledgerState.error =
        `Settlement unverified${where}: ${reason}. The transfer was not confirmed; do not resend.`;
    } else {
      ledgerState.error = null;
    }
    return;
  }

  if (plain.kind === LEDGER_EVENT.BALANCE_RECEIPT) {
    if (typeof plain.balance === 'number') {
      ledgerState.balance = plain.balance;
      ledgerState.verifiedAt = Date.now();
    }
    if (typeof plain.height === 'number') {
      ledgerState.height = plain.height;
    }
    ledgerState.error = null;
    return;
  }

  if (plain.kind === LEDGER_EVENT.INVALID) {
    // Never mutate the verified balance on an invalid event.
    ledgerState.error = plain.reason ?? 'ledger_event_invalid';
  }
}

/**
 * Append a UI-shaped activity entry, de-duplicating by id and capping the list.
 * @param {{ id: string, type: string, from: string|null, to: string|null, amount: number|null, signedBy: string|null, timestamp: string }} entry
 */
function _recordActivity(entry) {
  if (!entry || !entry.id) return;
  if (ledgerState.activity.some((existing) => existing.id === entry.id)) return;
  const next = [...ledgerState.activity, entry];
  if (next.length > MAX_ACTIVITY_ENTRIES) {
    next.splice(0, next.length - MAX_ACTIVITY_ENTRIES);
  }
  ledgerState.activity = next;
}

/**
 * Normalized dedup key for an activity entry.
 *
 * A value movement is keyed by its ledger `entrySeq` (`v:<seq>`) so the same
 * movement recorded live and restored from persisted state collapses; a
 * settlement is keyed by its order hash (`s:<hash>`). Anything else keeps its
 * own `id`.
 *
 * @param {object} entry
 * @returns {string}
 */
function _activityKey(entry) {
  if (!entry || typeof entry !== 'object') return String(entry);
  // A settlement carries both the resolving ledger `entrySeq` and its order
  // hash, and must always key by the order hash. Checking `entrySeq` first
  // would seed an existing settlement under `v:<seq>` while the persisted
  // record is re-inserted under `s:<hash>`, yielding two entries with the same
  // `id` (a duplicate keyed-each key that freezes the Activity table).
  if (entry.type === ACTIVITY_TYPES.SETTLEMENT) return `s:${entry.orderHash}`;
  if (entry.entrySeq != null) return `v:${entry.entrySeq}`;
  if (entry.orderHash != null) return `s:${entry.orderHash}`;
  return entry.id != null ? String(entry.id) : `unknown:${Math.random()}`;
}

/**
 * Rebuild `ledgerState.activity` from persisted ledger state so a reload keeps
 * its history (value notices) and every terminal settlement outcome.
 *
 * Merges three sources, deduped by `_activityKey` and capped at
 * `MAX_ACTIVITY_ENTRIES`, oldest-first by timestamp:
 *   1. persisted value-notice activity (`ClientNode.ledger_activity()`);
 *   2. persisted settlement records (`ClientNode.settlement_records()`);
 *   3. live entries already in `ledgerState.activity` (from `_recordActivity`).
 *
 * Persisted data wins on an overlapping key. Settlement records carry no
 * timestamp, so we reuse the timestamp of a matching live entry (by order hash)
 * when one exists and otherwise stamp them all with the reconstruction time —
 * keeping the wasm list's oldest-first order via a stable sort.
 *
 * Idempotent and cheap (bounded by the two capped wasm lists). If the wasm
 * getters are missing or throw, the existing list is kept and a warning is
 * logged once.
 *
 * @param {object} [node] Live client node to read from.
 */
function _rebuildActivityFromState(node = _clientNode) {
  if (_useMock || !node) return;
  if (
    typeof node.ledger_activity !== 'function' ||
    typeof node.settlement_records !== 'function'
  ) {
    _warnOnce(
      'activity-rebuild-unavailable',
      '[api] ledger_activity/settlement_records unavailable; keeping the current activity list',
    );
    return;
  }

  let next;
  try {
    const existing = Array.isArray(ledgerState.activity) ? ledgerState.activity : [];
    // Seed with live entries first; persisted sources overwrite on key overlap.
    const byKey = new Map();
    const stampByOrderHash = new Map();
    for (const entry of existing) {
      if (!entry) continue;
      byKey.set(_activityKey(entry), entry);
      const orderHash = entry.orderHash ?? entry.id;
      if (typeof orderHash === 'string' && !stampByOrderHash.has(orderHash)) {
        stampByOrderHash.set(orderHash, entry.timestamp);
      }
    }
    const signedBy = _parentNodeIdFrom(node);
    const fallbackStamp = new Date().toISOString();

    // 1. Persisted value notices.
    const activityDtos = node.ledger_activity() ?? [];
    try {
      for (const dto of activityDtos) {
        const entrySeq = dto.entry_seq;
        const entryHash = dto.entry_hash ?? null;
        const issuedAt = Number(dto.issued_at);
        const timestamp = Number.isFinite(issuedAt)
          ? new Date(issuedAt * 1000).toISOString()
          : fallbackStamp;
        byKey.set(`v:${entrySeq}`, {
          id: entryHash ?? `v:${entrySeq}`,
          type: ACTIVITY_TYPES.TRANSFER,
          from: dto.from ?? null,
          to: dto.to ?? null,
          amount: typeof dto.amount === 'number' ? dto.amount : null,
          signedBy,
          timestamp,
          entrySeq,
          entryHash,
        });
      }
    } finally {
      for (const dto of activityDtos) dto.free?.();
    }

    // 2. Persisted settlement records (summary of every terminal outcome).
    const settlementDtos = node.settlement_records() ?? [];
    try {
      for (const record of settlementDtos) {
        const orderHash = record.order_hash ?? null;
        const timestamp =
          (orderHash && stampByOrderHash.get(orderHash)) || fallbackStamp;
        byKey.set(`s:${orderHash}`, {
          id: `s:${orderHash}`,
          type: ACTIVITY_TYPES.SETTLEMENT,
          from: null,
          to: record.counterparty ?? null,
          amount: typeof record.amount === 'number' ? record.amount : null,
          status: record.status ?? null,
          reason: record.reason ?? null,
          // The failing hop for a `partial` settlement; null otherwise.
          failedAt: record.failed_at ?? null,
          orderHash,
          timestamp,
          entrySeq: record.entry_seq ?? null,
        });
      }
    } finally {
      for (const record of settlementDtos) record.free?.();
    }

    next = [...byKey.values()].sort((a, b) =>
      String(a.timestamp).localeCompare(String(b.timestamp)),
    );
    if (next.length > MAX_ACTIVITY_ENTRIES) {
      next = next.slice(next.length - MAX_ACTIVITY_ENTRIES);
    }
  } catch (err) {
    _warnOnce('activity-rebuild', '[api] activity rebuild failed; keeping the current list', err);
    return;
  }
  ledgerState.activity = next;
}

/**
 * Resync the balance/height/pin/pending fields of `ledgerState` from the
 * authoritative wasm `ledger_status()` snapshot.
 *
 * The in-flight count is read from `pending_orders()` (the explicit getter)
 * when available, falling back to `ledger_status().pending`; the two describe
 * the same set, so behavior is unchanged.
 */
function _syncLedgerStoreFromStatus() {
  if (_useMock || !_clientNode) return;
  let status;
  try {
    status = _readLedgerStatus(_clientNode);
  } catch (err) {
    _warnOnce('ledger-status', '[api] ledger status read failed', err);
    return;
  }
  const pendingOrders = _readPendingOrders(_clientNode);
  ledgerState.balance = status.balance;
  ledgerState.height = status.height;
  ledgerState.pinnedLedger = status.pinnedLedger;
  ledgerState.stateRoot = status.stateRoot;
  ledgerState.pending = pendingOrders != null ? pendingOrders.length : status.pending;
  ledgerState.trustEstablished = _trustEstablished;
  if (status.balance != null && ledgerState.verifiedAt == null) {
    // A balance restored from persisted state is still verified; stamp it.
    ledgerState.verifiedAt = Date.now();
  }
}

/**
 * Copy a wasm `LedgerStatusDto` to a plain object and free it.
 * @param {object} node
 * @returns {{ address: string|null, parent: string|null, balance: number|null, height: number|null, pinnedLedger: string|null, stateRoot: string|null, pending: number, activity: number }}
 */
function _readLedgerStatus(node) {
  const dto = node.ledger_status();
  try {
    return {
      address: dto.address ?? null,
      parent: dto.parent ?? null,
      balance: dto.balance ?? null,
      height: dto.height ?? null,
      pinnedLedger: dto.pinned_ledger ?? null,
      stateRoot: dto.state_root ?? null,
      pending: dto.pending,
      activity: dto.activity,
    };
  } finally {
    dto.free?.();
  }
}

// ── Blob-derived read getters (R1) ────────────────────────────
//
// These wasm getters expose detail that used to be reachable only by decoding
// the `cawala.state.v1` / `cawala.ledger.v1` blobs. They are pure reads: each
// helper copies the DTO to a plain object and frees every wasm handle it
// created. Tolerates an older build without the getter.

/**
 * Copy one `PendingOrderDto` to a plain object and free it (including its
 * nested `pinned_leaf` handle). Read-once/free-once.
 * @param {object} dto
 * @returns {object}
 */
function _readPendingOrder(dto) {
  const pinnedLeaf = dto.pinned_leaf ?? null;
  try {
    return {
      from: dto.from,
      to: dto.to,
      amount: dto.amount,
      nonce: dto.nonce,
      expiry: dto.expiry,
      operator: dto.operator,
      authNonce: dto.auth_nonce,
      orderHash: dto.order_hash,
      signature: dto.signature,
      sentAt: dto.sent_at,
      payeeAddr: dto.payee_addr ?? null,
      payerLeaf: Boolean(dto.payer_leaf),
      pinnedLeaf: pinnedLeaf
        ? { nodeId: pinnedLeaf.node_id, ledger: pinnedLeaf.ledger }
        : null,
    };
  } finally {
    pinnedLeaf?.free?.();
    dto.free?.();
  }
}

/**
 * The persisted in-flight payment orders, as plain objects. `null` when this
 * client build has no `pending_orders()` getter (so callers can fall back to
 * the aggregate count rather than reading it as an empty set).
 * @param {object|null} [node]
 * @returns {Array<object>|null}
 */
function _readPendingOrders(node = _clientNode) {
  if (!node || typeof node.pending_orders !== 'function') return null;
  let dtos = [];
  try {
    dtos = node.pending_orders() ?? [];
  } catch (err) {
    _warnOnce('pending-orders', '[api] pending_orders read failed', err);
    // Null (not empty) so the count falls back to `ledger_status().pending`.
    return null;
  }
  // Each `_readPendingOrder` frees its own DTO (and nested pin).
  return dtos.map(_readPendingOrder);
}

/**
 * The leaf ledger keys pinned in local ledger state, as plain objects
 * (`{ nodeId, ledger }`). Empty when the getter is unavailable.
 * @param {object|null} [node]
 * @returns {Array<{ nodeId: string, ledger: string }>}
 */
function _readPinnedLeafKeys(node = _clientNode) {
  if (!node || typeof node.pinned_leaf_keys !== 'function') return [];
  let dtos = [];
  try {
    dtos = node.pinned_leaf_keys() ?? [];
    return dtos.map((dto) => {
      try {
        return { nodeId: dto.node_id, ledger: dto.ledger };
      } finally {
        dto.free?.();
      }
    });
  } catch (err) {
    _warnOnce('pinned-leaf-keys', '[api] pinned_leaf_keys read failed', err);
    return [];
  }
}

/**
 * The in-flight outbound join request, as a plain object, or null.
 * @param {object|null} [node]
 * @returns {object|null}
 */
function _readPendingJoinOutbound(node = _clientNode) {
  if (!node || typeof node.pending_join_outbound !== 'function') return null;
  let dto;
  try {
    dto = node.pending_join_outbound();
  } catch (err) {
    _warnOnce('pending-join-outbound', '[api] pending_join_outbound read failed', err);
    return null;
  }
  if (!dto) return null;
  try {
    return {
      node: dto.node,
      kind: dto.kind,
      operator: dto.operator,
      ledger: dto.ledger ?? null,
      desiredSlot: dto.desired_slot ?? null,
      locationHint: dto.location_hint ?? null,
      nonce: dto.nonce,
      expiry: dto.expiry,
      parent: dto.parent,
      pinnedOperator: dto.pinned_operator ?? null,
      sentAt: dto.sent_at,
    };
  } finally {
    dto.free?.();
  }
}

/**
 * The on-disk blob versions this client writes, or nulls when unavailable.
 * @param {object|null} [node]
 * @returns {{ stateVersion: number|null, ledgerVersion: number|null }}
 */
function _readClientStateInfo(node = _clientNode) {
  if (!node || typeof node.client_state_info !== 'function') {
    return { stateVersion: null, ledgerVersion: null };
  }
  let info;
  try {
    info = node.client_state_info();
  } catch (err) {
    _warnOnce('client-state-info', '[api] client_state_info read failed', err);
    return { stateVersion: null, ledgerVersion: null };
  }
  if (!info) return { stateVersion: null, ledgerVersion: null };
  try {
    return {
      stateVersion: info.state_version ?? null,
      ledgerVersion: info.ledger_version ?? null,
    };
  } finally {
    info.free?.();
  }
}

/**
 * The persisted in-flight payment orders (full detail), for UI reconstruction
 * after a reload. Empty when unavailable.
 * @returns {Array<object>}
 */
export function getPendingOrders() {
  return _readPendingOrders() ?? [];
}

/**
 * The authoritative-local TOFU leaf pins, for the trust surface.
 * @returns {Array<{ nodeId: string, ledger: string }>}
 */
export function getPinnedLeafKeys() {
  if (_useMock || !_clientNode) return [];
  return _readPinnedLeafKeys();
}

/**
 * The in-flight outbound join request, if any.
 * @returns {object|null}
 */
export function getPendingJoinOutbound() {
  if (_useMock || !_clientNode) return null;
  return _readPendingJoinOutbound();
}

/**
 * The current on-disk state/ledger blob versions.
 * @returns {{ stateVersion: number|null, ledgerVersion: number|null }}
 */
export function getClientStateInfo() {
  if (_useMock || !_clientNode) return { stateVersion: null, ledgerVersion: null };
  return _readClientStateInfo();
}

/**
 * Whether TOFU trust anchors were restored from the persisted ledger cache at
 * boot. False on a fresh origin (no cache): trust is not established.
 * @returns {boolean}
 */
export function isTrustEstablished() {
  return _trustEstablished;
}

/**
 * The trust-anchor surface. `established` is whether pins were restored from
 * the persisted cache; `needsReestablish` is the complement in live mode.
 *
 * Fail-closed: when `needsReestablish` is true the UI must not present a pin as
 * TOFU-established, even if one appears in-session. Preventing the wasm layer
 * from auto-pinning in the first place needs a node change (follow-up).
 *
 * @returns {{ established: boolean, needsReestablish: boolean, pinnedLedger: string|null, pinnedLeafKeys: Array<{ nodeId: string, ledger: string }>, mock: boolean }}
 */
export function getTrustState() {
  if (_useMock || !_clientNode) {
    return {
      established: false,
      needsReestablish: false,
      pinnedLedger: null,
      pinnedLeafKeys: [],
      mock: true,
    };
  }
  let pinnedLedger = null;
  try {
    pinnedLedger = _readLedgerStatus(_clientNode).pinnedLedger;
  } catch (err) {
    _warnOnce('trust-ledger', '[api] trust state ledger read failed', err);
  }
  return {
    established: _trustEstablished,
    needsReestablish: !_trustEstablished,
    pinnedLedger,
    pinnedLeafKeys: _readPinnedLeafKeys(_clientNode),
    mock: false,
  };
}

/**
 * A node's parent node id, if joined (used as the activity `signedBy`).
 * Tolerates a missing/unjoined node and never throws.
 * @param {object|null} node
 * @returns {string|null}
 */
function _parentNodeIdFrom(node) {
  if (!node) return null;
  let snapshot;
  let parent;
  try {
    snapshot = node.local_snapshot();
    parent = snapshot.parent;
    return parent?.node_id ?? null;
  } catch {
    return null;
  } finally {
    parent?.free?.();
    snapshot?.free?.();
  }
}

/**
 * This client's parent node id, if joined (used as the activity `signedBy`).
 * @returns {string|null}
 */
function _parentNodeId() {
  return _parentNodeIdFrom(_clientNode);
}

/**
 * Fire a best-effort `requestBalance()` when an address is assigned, throttled
 * so init + spawnClient do not issue duplicate requests.
 */
function _requestBalanceIfJoined() {
  if (_useMock || !_clientNode) return;
  let address = null;
  try {
    address = _readJoinStatus(_clientNode).address ?? null;
  } catch {
    /* ignore */
  }
  if (!address) return;
  const now = Date.now();
  if (now - _lastBalanceRequestAt < 1000) return;
  _lastBalanceRequestAt = now;
  void requestBalance();
}

// ── Client lifecycle ──────────────────────────────────────────

/**
 * Spawn a client node (or mock equivalent). In live mode the node itself is
 * spawned by `initApi()`; this returns its identity/address.
 * @returns {Promise<{ endpointId: string, address: string|null }>}
 */
export async function spawnClient() {
  if (_useMock) {
    await mockDelay(300);
    // Mock is a distinct neutral state, never a live green "Connected".
    _syncConnectionStatusIntoStore();
    _syncAdministeredNode();
    return {
      endpointId: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      address: '0.3.1',
    };
  }
  const node = _requireNode();
  const status = _readJoinStatus(node);
  const address = status.address ?? null;
  if (address) _requestBalanceIfJoined();
  // `_spawnRealNode` already mirrored the address; re-derive so a restored
  // join shows green immediately rather than after the first poller tick.
  _syncConnectionStatusIntoStore();
  return {
    endpointId: node.endpoint_id(),
    address,
  };
}

/**
 * Spawn a client with a known address (for join flow). In live mode this is an
 * alias of `spawnClient()`: the control client derives its own address from the
 * join handshake, so the hint is informational only.
 * @param {string} address
 * @returns {Promise<{ endpointId: string, address: string|null }>}
 */
export async function spawnClientWithAddress(address) {
  if (_useMock) {
    await mockDelay(300);
    return {
      endpointId: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      address,
    };
  }
  return spawnClient();
}

/**
 * Destroy the current client.
 */
export function destroyClient() {
  _stopControlPoller();
  if (_clientNode) {
    try {
      _persistState();
    } catch {
      /* best effort */
    }
    try {
      _persistLedgerState();
    } catch {
      /* best effort */
    }
    try {
      _clientNode.free?.();
    } catch {
      /* ignore */
    }
    _clientNode = null;
  }
  _pendingSends.clear();
  _ethRegisteredFor = null;
  _spawnedSeedHex = null;
  _releaseIdentityLock();
}

// ── Portable identity ─────────────────────────────────────────

/**
 * Tear down the live client without persisting its state. Used before swapping
 * or wiping an identity so stale state/events can never be written under the
 * new identity's keys.
 */
function _teardownClient() {
  _stopControlPoller();
  if (_clientNode) {
    // Drop the in-memory user identity before the node is freed so no further
    // V4 order can be signed on a torn-down/being-replaced identity.
    try {
      _clientNode.clear_user_identity?.();
    } catch {
      /* ignore */
    }
    try {
      _clientNode.free?.();
    } catch {
      /* ignore */
    }
    _clientNode = null;
  }
  _ethRegisteredFor = null;
  _releaseIdentityLock();
  _memorySeed = null;
  _identitySource = 'memory';
  _spawnedSeedHex = null;
}

/**
 * Read the current identity seed as hex, preferring localStorage and falling
 * back to the in-session seed.
 * @returns {string|null}
 */
function _readStoredSeedHex() {
  let storedHex = null;
  try {
    storedHex = window.localStorage.getItem(IDENTITY_KEY);
  } catch (err) {
    _warnOnce('identity-export-read', '[api] localStorage unavailable for identity export', err);
  }
  if (typeof storedHex === 'string' && /^[0-9a-fA-F]{64}$/.test(storedHex)) {
    return storedHex.toLowerCase();
  }
  if (_memorySeed) return _bytesToHex(_memorySeed);
  return null;
}

/**
 * Write (or, for a null blob, remove) an identity-scoped base64 blob.
 * @param {string} base
 * @param {string} nodeId
 * @param {string|null} b64
 */
function _writeScopedB64(base, nodeId, b64) {
  try {
    if (typeof b64 === 'string') {
      window.localStorage.setItem(_scopedKey(base, nodeId), b64);
    } else {
      window.localStorage.removeItem(_scopedKey(base, nodeId));
    }
  } catch (err) {
    _warnOnce(`${base}-import-write`, `[api] could not write ${base} for the imported identity`, err);
  }
}

/**
 * Remove an identity-scoped blob. Best-effort.
 * @param {string} base
 * @param {string} nodeId
 */
function _removeScopedBlob(base, nodeId) {
  try {
    window.localStorage.removeItem(_scopedKey(base, nodeId));
  } catch (err) {
    _warnOnce(`${base}-remove`, `[api] could not remove ${base} for the identity`, err);
  }
}

/**
 * Remove the legacy (pre-portability) un-namespaced state/ledger blobs.
 */
function _removeLegacyBlobs() {
  try {
    window.localStorage.removeItem(STATE_KEY);
    window.localStorage.removeItem(LEDGER_KEY);
  } catch (err) {
    _warnOnce('legacy-remove', '[api] could not remove legacy state/ledger keys', err);
  }
}

/**
 * Encrypt and serialize the current identity (seed + opaque state/ledger blobs)
 * into a passphrase-protected, portable bundle string.
 *
 * Requires a live client and a stored seed. Does not mutate any state.
 *
 * @param {string} passphrase
 * @returns {Promise<string>} Serialized identity bundle.
 */
export async function exportIdentityBundle(passphrase) {
  const node = _requireNode();
  const seedHex = _readStoredSeedHex();
  if (!seedHex) {
    throw new Error('No identity to export. This device has no stored account key.');
  }
  const nodeId = node.endpoint_id();

  let stateB64 = null;
  let ledgerB64 = null;
  try {
    const stateBytes = node.export_state();
    stateB64 = stateBytes ? _bytesToBase64(stateBytes) : null;
  } catch (err) {
    _warnOnce('export-state', '[api] export_state failed; exporting the identity without client state', err);
  }
  try {
    const ledgerBytes = node.export_ledger_state();
    ledgerB64 = ledgerBytes ? _bytesToBase64(ledgerBytes) : null;
  } catch (err) {
    _warnOnce('export-ledger', '[api] export_ledger_state failed; exporting the identity without ledger state', err);
  }

  const bundle = await idb.encryptIdentityBundle({
    seedHex,
    stateB64,
    ledgerB64,
    nodeId,
    passphrase,
  });
  return idb.serializeIdentityBundle(bundle);
}

/**
 * Inspect a serialized bundle's cleartext metadata without decrypting it.
 *
 * @param {string} text
 * @returns {{ version: number, nodeId: string }}
 */
export function inspectIdentityBundle(text) {
  const bundle = idb.parseIdentityBundle(text);
  const meta = idb.inspectIdentityBundle(bundle);
  return { version: meta.version, nodeId: meta.nodeId };
}

/**
 * Decrypt and install an identity bundle, replacing any current identity.
 *
 * Tears the live client down, writes the recovered seed to `cawala.identity.v1`
 * and the recovered state/ledger blobs under the bundle's `nodeId` keys. Does
 * NOT reload; the caller reloads so `initApi()` restores the new identity.
 *
 * JS cannot derive the endpoint id from an Ed25519 seed without the wasm
 * client, so the cleartext `nodeId` is trusted here. It is bound into the
 * AES-GCM AAD, so a tampered value fails decryption before we get this far.
 *
 * @param {string} text
 * @param {string} passphrase
 * @returns {Promise<{ nodeId: string }>}
 */
export async function importIdentityBundle(text, passphrase) {
  const bundle = idb.parseIdentityBundle(text);
  const meta = idb.inspectIdentityBundle(bundle);
  const decrypted = await idb.decryptIdentityBundle(bundle, passphrase);

  if (typeof decrypted.seedHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(decrypted.seedHex)) {
    throw new Error('Malformed identity bundle');
  }
  const seedHex = decrypted.seedHex.toLowerCase();
  const nodeId = meta.nodeId;

  // Tear down before writing so nothing from the old identity can leak through.
  _teardownClient();

  try {
    window.localStorage.setItem(IDENTITY_KEY, seedHex);
  } catch (err) {
    _warnOnce('identity-import-write', '[api] could not persist the imported identity', err);
  }

  // Never mix blobs across identities: overwrite when present, remove when not.
  _writeScopedB64(STATE_KEY, nodeId, decrypted.stateB64);
  _writeScopedB64(LEDGER_KEY, nodeId, decrypted.ledgerB64);
  _removeLegacyBlobs();

  return { nodeId };
}

/**
 * Wipe this device's identity: tear the live client down and remove the seed,
 * the current identity's state/ledger blobs, and the legacy blobs. Does NOT
 * reload; the caller reloads to start fresh.
 *
 * @returns {Promise<void>}
 */
export async function wipeIdentity() {
  let nodeId = null;
  if (_clientNode) {
    try {
      nodeId = _clientNode.endpoint_id();
    } catch {
      /* ignore */
    }
  }

  _teardownClient();

  // Drop the R3 user-identity record too: "remove identity from this device"
  // means this device forgets both identities. The recovery phrase (never
  // stored) still restores the user identity elsewhere.
  userIdentity.clearUserIdentity();
  refreshUserIdentity();

  try {
    window.localStorage.removeItem(IDENTITY_KEY);
  } catch (err) {
    _warnOnce('identity-wipe', '[api] could not remove the stored identity', err);
  }
  if (nodeId) {
    _removeScopedBlob(STATE_KEY, nodeId);
    _removeScopedBlob(LEDGER_KEY, nodeId);
  }
  _removeLegacyBlobs();
}

// ── Identity & connection ─────────────────────────────────────

/**
 * Get the current endpoint ID.
 * @returns {string}
 */
export function getEndpointId() {
  if (_useMock) return 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  return _clientNode ? _clientNode.endpoint_id() : '';
}

/**
 * Get the current join-assigned address.
 * @returns {string|null}
 */
export function getAddress() {
  if (_useMock) return '0.3.1';
  if (!_clientNode) return null;
  return _readJoinStatus(_clientNode).address ?? null;
}

/**
 * Get connection status: whether this client is attached to a parent node.
 *
 * Mirrors the derivation that keeps `clientState.connectionStatus` current;
 * it no longer reports CONNECTED merely because a wasm client exists.
 * @returns {string} One of CONNECTION.*
 */
export function getConnectionStatus() {
  return _deriveConnectionStatus();
}

// ── Ping (existing wasm surface) ──────────────────────────────

/**
 * Send a ping to another endpoint.
 * @param {string} targetEndpointId
 * @param {string} payload
 * @returns {Promise<string>} Pong payload.
 */
export async function ping(targetEndpointId, payload) {
  if (_useMock) {
    await mockDelay(200);
    return payload;
  }
  return _requireNode().ping(targetEndpointId, payload);
}

// ── Messaging (existing wasm surface) ─────────────────────────

/**
 * Send an envelope to the network. The control client has no messaging
 * address, so this throws a clear error instead of surfacing a wasm error.
 * @param {string} nextHop - Endpoint ID of the direct neighbor.
 * @param {string} dst - Final destination address.
 * @param {number} msgType - Message type discriminator.
 * @param {Uint8Array} payload - Raw payload bytes.
 * @returns {Promise<string>} Ack status string (one of ENVELOPE_ACK.*).
 */
export async function sendEnvelope(nextHop, dst, msgType, payload) {
  if (_useMock) {
    await mockDelay(150);
    return ENVELOPE_ACK.DELIVERED;
  }
  const node = _requireNode();
  if (node.address() == null) {
    throw new Error(
      'sendEnvelope is unavailable: this control-only client has no messaging address. ' +
        'Open a node with an asserted address to send envelopes.',
    );
  }
  return node.send_envelope(nextHop, dst, msgType, payload);
}

/**
 * Try to receive the next envelope (non-blocking).
 * @returns {object|null} ReceivedEnvelope plain object, or null if empty /
 *   unavailable on this control client.
 */
export function tryRecvEnvelope() {
  if (_useMock) return null;
  if (!_clientNode) return null;
  try {
    const env = _clientNode.try_recv_envelope();
    if (!env) return null;
    const plain = {
      src_addr: env.src_addr,
      src_node: env.src_node,
      dst: env.dst,
      msg_id_hex: env.msg_id_hex,
      msg_type: env.msg_type,
      payload: env.payload,
    };
    env.free?.();
    return plain;
  } catch (err) {
    // Control-only clients have no envelope receive queue; treat as empty.
    _warnOnce('envelope-recv', '[api] try_recv_envelope unavailable on this client', err);
    return null;
  }
}

// ── Ledger / value transfer ───────────────────────────────────

/**
 * Pin the payee leaf's ledger key (from a receive URI's `ln`/`lk`) before
 * sending a payment.
 *
 * Once pinned, a terminal inclusion proof for that leaf must verify under
 * exactly this key; a mismatch is reported by the wasm ledger as an
 * `"unverified"` settlement, never as success. The pin is stored in the
 * secret-free ledger state, so it survives export/import round trips.
 *
 * @param {string} nodeId Payee leaf node id (the URI's `ln`).
 * @param {string} ledgerHex Payee leaf ledger public key, 64 hex chars (`lk`).
 * @returns {Promise<void>}
 */
export async function pinPayeeLeaf(nodeId, ledgerHex) {
  if (typeof nodeId !== 'string' || !nodeId.trim()) {
    throw new Error('A payee leaf node id is required to pin the payee leaf.');
  }
  if (typeof ledgerHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(ledgerHex)) {
    throw new Error('The payee leaf ledger key must be 64 hex characters.');
  }

  if (_useMock) {
    await mockDelay(50);
    return; // no-op: mock mode has no verifiable settlement
  }

  const node = _requireNode();
  if (typeof node.pin_payee_leaf !== 'function') {
    throw new Error('This client build does not support pinning a payee leaf.');
  }
  // Let a wasm rejection propagate: the caller must not send on a failed pin.
  await node.pin_payee_leaf(nodeId.trim(), ledgerHex.toLowerCase());
}

/**
 * Normalize the optional payee-pin argument accepted by `sendPayment`.
 *
 * Accepts either a bare 64-hex ledger key or a parsed-payee-shaped object
 * (`{ leafNodeId, ledgerKeyHex }`, `{ ln, lk }`, or `{ nodeId, ledgerKeyHex }`).
 * Returns `null` when no pin was supplied.
 *
 * @param {string|object|null|undefined} pin
 * @param {string} fallbackNodeId Payee node id used when the pin is a bare key.
 * @returns {{ nodeId: string, ledgerHex: string }|null}
 */
function _normalizePayeePin(pin, fallbackNodeId) {
  if (!pin) return null;
  if (typeof pin === 'string') {
    return { nodeId: fallbackNodeId, ledgerHex: pin };
  }
  if (typeof pin === 'object') {
    const ledgerHex = pin.ledgerKeyHex ?? pin.lk ?? pin.payeeLedgerHex ?? null;
    if (!ledgerHex) return null;
    const nodeId =
      pin.leafNodeId ?? pin.ln ?? pin.payeeLeafNodeId ?? pin.nodeId ?? fallbackNodeId;
    return { nodeId, ledgerHex };
  }
  return null;
}

/**
 * Send a payment to a payee (cross-leaf or same-leaf).
 *
 * `to` is the payee's endpoint id (node id) and `toAddress` is their octal
 * address (both normally from a receive URI). `amount` is in whole Cawala
 * units. The order is operator-signed and persisted as pending *before* it is
 * dialed, so a racing `"order_result"` event can always be matched; the
 * terminal status arrives through the ledger-event poller as one of
 * `applied`/`duplicate`/`partial`/`rejected`/`indeterminate`/`unverified`.
 *
 * The optional `payeePin` is the parsed payee leaf pin (the receive URI's
 * `ln`/`lk`): a bare 64-hex ledger key or a parsed-payee-shaped object. When
 * present, the leaf key is pinned *before* the order is sent; if pinning fails
 * the payment is aborted and the error surfaced.
 *
 * @param {string} to Recipient node id.
 * @param {string} toAddress Recipient octal address (e.g. "0.3.2").
 * @param {number} amount Whole, positive Cawala units.
 * @param {string|object|null} [payeePin] Parsed payee leaf pin (`lk` hex and/or `ln` id).
 * @returns {Promise<{ orderHash: string, ack: string }>}
 */
export async function sendPayment(to, toAddress, amount, payeePin = null) {
  const pin = _normalizePayeePin(payeePin, typeof to === 'string' ? to.trim() : to);

  if (pin) {
    try {
      await pinPayeeLeaf(pin.nodeId, pin.ledgerHex);
    } catch (err) {
      throw new Error(
        `Payment not sent: could not pin the payee leaf (${_errorMessage(err)}).`,
      );
    }
  }

  if (_useMock) {
    await mockDelay(500);
    const numeric = Number(amount);
    const orderHash = _randomHex32();
    _recordActivity({
      id: orderHash,
      type: ACTIVITY_TYPES.TRANSFER,
      from: getAddress(),
      to: typeof to === 'string' ? to : null,
      amount: Number.isFinite(numeric) ? numeric : null,
      signedBy: getEndpointId(),
      timestamp: new Date().toISOString(),
    });
    return { orderHash, ack: ENVELOPE_ACK.DELIVERED };
  }

  if (typeof to !== 'string' || !to.trim()) {
    throw new Error('Enter the recipient node id.');
  }
  if (typeof toAddress !== 'string' || !toAddress.trim()) {
    throw new Error('Enter the recipient address.');
  }
  const numeric = Number(amount);
  if (!Number.isFinite(numeric)) {
    throw new Error('Enter a valid amount.');
  }
  if (!Number.isInteger(numeric)) {
    throw new Error('Amount must be a whole number.');
  }
  if (numeric <= 0) {
    throw new Error('Amount must be greater than zero.');
  }
  if (numeric > Number.MAX_SAFE_INTEGER) {
    throw new Error('Amount is too large (maximum is 9,007,199,254,740,991).');
  }

  const node = _requireNode();
  let outcome;
  try {
    outcome = await node.send_payment(to.trim(), toAddress.trim(), numeric);
  } catch (err) {
    throw new Error(`Payment failed: ${_errorMessage(err)}`);
  }

  let orderHash;
  let ack;
  try {
    orderHash = outcome.order_hash_hex;
    ack = outcome.ack;
  } finally {
    outcome.free?.();
  }

  _pendingSends.set(orderHash, {
    orderHash,
    to: to.trim(),
    toAddress: toAddress.trim(),
    amount: numeric,
    ack,
    status: 'pending',
    reason: null,
    failedAt: null,
    sentAt: Date.now(),
    resolvedAt: null,
  });
  _persistLedgerState();
  // Pick up a terminal result that raced the ack, and resync pending counts.
  _drainLedgerEvents();
  return { orderHash, ack };
}

/**
 * Ask the routing leaf for a signed balance receipt.
 *
 * The verified balance arrives asynchronously as a `balance_receipt` ledger
 * event. This is a safe no-op when not initialized; a wasm error (e.g. not
 * joined) is surfaced on `ledgerState.error` rather than thrown.
 *
 * @returns {Promise<string|null>} The leaf's ack bucket, or null when unavailable.
 */
export async function requestBalance() {
  if (_useMock) {
    await mockDelay(150);
    return ENVELOPE_ACK.DELIVERED;
  }
  if (!_clientNode) return null;
  try {
    const ack = await _clientNode.request_balance();
    // A returned ack (`delivered`/`duplicate`/`rejected`) means the parent
    // answered, so this existing 20 s balance poll doubles as the parent
    // liveness probe. A thrown error is a transport failure (dial/timeout/no
    // route). Recording is best-effort and never gates the balance flow.
    parentLiveness.recordParentProbe(_parentNodeId(), true);
    return ack;
  } catch (err) {
    parentLiveness.recordParentProbe(_parentNodeId(), false);
    const message = _errorMessage(err);
    _warnOnce('balance-request', '[api] request_balance failed', err);
    ledgerState.error = message;
    return null;
  }
}

// ── Parent liveness (passive, informational only) ─────────────

/**
 * Passive parent-liveness status for the informational UI notice.
 *
 * This is a **read-only, informational** signal with no authority and no
 * gating: it is derived from the existing parent-facing balance poll (see
 * `requestBalance`) and the `cawala.recovery.v1` localStorage tracker. The
 * recovery *action* stays out of the API layer — the UI reuses `leave()` and
 * the join flow.
 *
 * `reachable` is true when the last probe succeeded (or none has failed yet);
 * `unreachableSince` is the first-failure timestamp while failing, else null.
 * The returned object has exactly the frozen keys
 * `{ parent, reachable, lastOkAt, unreachableSince, consecutiveFailures }`.
 *
 * @returns {{ parent: string|null, reachable: boolean, lastOkAt: number|null, unreachableSince: number|null, consecutiveFailures: number }}
 */
export function parentStatus() {
  const parent = _useMock || !_clientNode ? null : _parentNodeId();
  return parentLiveness.getParentStatus(parent);
}

/**
 * A plain snapshot of the verified ledger state.
 *
 * Prefers the live wasm `ledger_status()` DTO (freeing it) and falls back to
 * the reactive `ledgerState` store. `activity` is the number of recorded
 * entries; the entries themselves live in `ledgerState.activity`.
 *
 * @returns {{ address: string|null, parent: string|null, balance: number|null, height: number|null, pinnedLedger: string|null, stateRoot: string|null, pending: number, activity: number }}
 */
export function getLedgerStatus() {
  if (!_useMock && _clientNode) {
    return _readLedgerStatus(_clientNode);
  }
  return {
    address: getAddress(),
    parent: null,
    balance: ledgerState.balance,
    height: ledgerState.height,
    pinnedLedger: ledgerState.pinnedLedger,
    stateRoot: ledgerState.stateRoot,
    pending: ledgerState.pending,
    activity: ledgerState.activity.length,
  };
}

/**
 * Parse and validate a `cawala://pay?to=...&addr=...` receive URI.
 *
 * The URI may also carry the payee leaf's out-of-band pin
 * (`ln=<leaf node id>&lk=<64-hex ledger key>`); when present it is surfaced as
 * `leafNodeId`/`ledgerKeyHex` (aliases `ln`/`lk`) so the payer can pin the
 * leaf before sending and require the terminal proof to verify under that key.
 *
 * @param {string} uri - Raw receive URI from the user.
 * @returns {Promise<{ nodeId: string, address: string, leafNodeId: string|null, ledgerKeyHex: string|null, ln: string|null, lk: string|null }>}
 * @throws {Error} With a user-facing message if the URI is invalid.
 */
export async function parseReceiveUri(uri) {
  const trimmed = (uri || '').trim();
  if (!trimmed) {
    throw new Error('Paste a receive URI from the payee.');
  }

  if (_useMock) {
    await mockDelay(100);
    return _mockParseReceiveUri(trimmed);
  }

  if (!_wasmModule) {
    throw new Error('URI parsing is unavailable: the wasm client is not loaded.');
  }

  let info;
  try {
    info = _wasmModule.parse_receive_uri(trimmed);
  } catch (err) {
    throw new Error(`Invalid receive URI: ${_errorMessage(err)}`);
  }

  try {
    // wasm-bindgen getters are `leaf_node`/`leaf_ledger`; tolerate `ln`/`lk`
    // so this keeps working across a concurrent glue regeneration.
    const leafNodeId = info.leaf_node ?? info.ln ?? null;
    const ledgerKeyHex = info.leaf_ledger ?? info.lk ?? null;
    return {
      nodeId: info.node_id,
      address: info.address,
      leafNodeId,
      ledgerKeyHex,
      // Literal URI-parameter aliases for callers that mirror the wire names.
      ln: leafNodeId,
      lk: ledgerKeyHex,
    };
  } finally {
    info.free?.();
  }
}

/**
 * Mock receive URI parser. Recognises `cawala://pay?to=...&addr=...[&ln=...&lk=...]`.
 */
function _mockParseReceiveUri(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("That doesn't look like a receive URI. Ask the payee to send a fresh one.");
  }
  if (url.protocol !== 'cawala:' || url.host !== 'pay') {
    throw new Error("That doesn't look like a receive URI. Ask the payee to send a fresh one.");
  }

  const to = url.searchParams.get('to');
  const addr = url.searchParams.get('addr');
  if (!to || !addr) {
    throw new Error('Receive URI is missing required fields (to, addr).');
  }

  // Optional leaf pin: `ln`/`lk` must appear together, and `lk` must be 64-hex.
  const ln = url.searchParams.get('ln');
  const lk = url.searchParams.get('lk');
  if ((ln == null) !== (lk == null)) {
    throw new Error("Incomplete leaf pin: 'ln' and 'lk' must appear together.");
  }
  if (lk != null && !/^[0-9a-fA-F]{64}$/.test(lk)) {
    throw new Error('Leaf ledger key must be 64 hex characters.');
  }
  const leafNodeId = ln ?? null;
  const ledgerKeyHex = lk ? lk.toLowerCase() : null;
  return {
    nodeId: to,
    address: addr,
    leafNodeId,
    ledgerKeyHex,
    ln: leafNodeId,
    lk: ledgerKeyHex,
  };
}

/**
 * Get this client's payment receive URI.
 *
 * @returns {Promise<string>} The `cawala://pay?to=...&addr=...` URI, or null.
 */
export async function getReceiveUri() {
  if (_useMock) {
    await mockDelay(100);
    return `cawala://pay?to=z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK&addr=${getAddress()}`;
  }
  if (!_clientNode) return null;
  try {
    return _clientNode.receive_uri();
  } catch (err) {
    _warnOnce('receive-uri', '[api] receive_uri failed', err);
    return null;
  }
}

/**
 * Snapshot of the JS-tracked payments for UI status, keyed by order hash. Each
 * entry starts as `status: 'pending'` and is updated to `applied`/`duplicate`/
 * `partial`/`rejected`/`indeterminate`/`unverified` when the matching
 * `order_result` event is drained. `unverified` is terminal but not success.
 * The authoritative in-flight count is `ledgerState.pending`.
 *
 * Note: this map is per-session (not persisted), so sends from a previous page
 * load are not listed even though their orders may still be pending in the
 * wasm ledger state.
 *
 * @returns {Array<{ orderHash: string, to: string, toAddress: string, amount: number, ack: string, status: string, reason: string|null, failedAt: string|null, sentAt: number, resolvedAt: number|null }>}
 */
export function getPendingPayments() {
  return Array.from(_pendingSends.values(), (payment) => ({ ...payment }));
}

// ── Control messages ──────────────────────────────────────────

/** Typed error for admin actions that the web client cannot perform. */
export class AdminUnavailableError extends Error {
  constructor(action = 'admin action') {
    super(
      `Admin action "${action}" is not available in the web client. ` +
        'Run it from the node CLI: `cawala-node control approve|reject <endpoint-id>`.',
    );
    this.name = 'AdminUnavailableError';
    this.code = 'ADMIN_UNAVAILABLE';
  }
}

/**
 * Request to join a parent node.
 *
 * Accepts either a parsed invite object (from `parseInvite`, carrying `raw`),
 * a raw invite URI string, or a bare parent endpoint id.
 * @param {string|{ parent?: string, raw?: string, slot?: number, expiry?: number, operator?: string }} parsed
 * @param {string|null} [addressHint] Backward-compat unused hint.
 * @returns {Promise<{ status: string, reason?: string, rejectCode?: string }>}
 */
export async function requestJoin(parsed, addressHint) {
  if (_useMock) {
    await mockDelay(600);
    return { status: JOIN_OUTCOME.PENDING };
  }

  // Never join while the node is still on its pre-identity random NodeId: the
  // next reload would switch to the mnemonic-derived NodeId and orphan the
  // join. Normally create/restore re-activates before returning; this catches
  // a failed re-activation (or a race) and tells the user to reload.
  if (_transportIdentityIsStale()) {
    throw new Error(
      'Your account key changed but this browser\u2019s node has not switched to it yet. Reload the page before joining.',
    );
  }

  const node = _requireNode();
  let uri = null;
  let directParent = null;
  let slot = null;
  let expiry = null;
  let operatorHex = null;

  if (typeof parsed === 'string') {
    const trimmed = parsed.trim();
    if (trimmed.includes('://')) uri = trimmed;
    else directParent = trimmed;
  } else if (parsed && typeof parsed === 'object') {
    if (typeof parsed.raw === 'string' && parsed.raw.trim()) {
      uri = parsed.raw.trim();
    } else {
      directParent = parsed.parent ?? null;
    }
    slot = parsed.slot ?? null;
    expiry = parsed.expiry ?? null;
    operatorHex = parsed.operator ?? null;
  }

  let outcome;
  if (uri) {
    outcome = await node.join_via_invite(uri);
  } else if (directParent) {
    outcome = await node.join(directParent, slot, expiry, operatorHex);
  } else {
    throw new Error('Join request is missing a parent endpoint id or invite.');
  }

  const status = outcome.status;
  const reason = outcome.reason;
  const rejectCode = outcome.reject_code ?? null;
  outcome.free?.();
  _persistState();
  _drainControlEvents();
  const result = { status };
  if (reason) result.reason = reason;
  if (rejectCode) result.rejectCode = rejectCode;
  return result;
}

/**
 * Resolve the ancestor every admin write targets, or throw when admin mode is
 * still locked (the Admin page shows the unlock gate instead of these
 * actions, so this is a guard against stale UI state).
 *
 * @param {string} action verb phrase for the error copy, e.g. `approve a join`
 * @param {string} [nodeId] explicit target; defaults to the selected ancestor
 * @returns {string} the target node id
 */
function _requireAdminTarget(action, nodeId = undefined) {
  if (!adminLock.unlocked) {
    throw new Error(`Admin mode is locked. Unlock it from the Admin tab to ${action}.`);
  }
  if (nodeId != null) return String(nodeId).toLowerCase();
  const target = _normalizeTarget();
  if (target === SELF) {
    throw new Error(`Admin mode is pointed at this browser\u2019s own node: step up to an ancestor node to ${action}.`);
  }
  return target;
}

/**
 * Approve a pending join request on the current admin target.
 *
 * The wasm call may reject with a `JsError` whose message is
 * `admin request rejected: <stable_code>`.
 *
 * @param {string} childEndpointId
 * @param {number|null} [slot]
 * @returns {Promise<{ status: string, address: string|null, delivery: string }>}
 */
export async function approveJoin(childEndpointId, slot = null) {
  const target = _requireAdminTarget('approve a join request');
  if (_useMock) {
    await mockDelay(400);
    const s = slot ?? 4;
    return { status: 'approved', address: `0.3.${s}`, delivery: 'delivered' };
  }

  const node = _requireNode();
  const dto = await node.admin_approve_join(target, childEndpointId, slot);
  try {
    return {
      status: 'approved',
      address: dto.address ?? null,
      delivery: dto.delivery,
    };
  } finally {
    dto.free?.();
  }
}

/**
 * Reject a pending join request on the current admin target.
 *
 * @param {string} childEndpointId
 * @param {string|null} [reason]
 * @returns {Promise<{ status: string, delivery: string }>}
 */
export async function rejectJoin(childEndpointId, reason = null) {
  const target = _requireAdminTarget('reject a join request');
  if (_useMock) {
    await mockDelay(300);
    return { status: 'rejected', delivery: 'delivered' };
  }

  const node = _requireNode();
  const dto = await node.admin_reject_join(target, childEndpointId, reason);
  try {
    return { status: 'rejected', delivery: dto.delivery };
  } finally {
    dto.free?.();
  }
}

/**
 * Re-send a previously stored join decision (approve or reject) to a child.
 *
 * @param {string} childEndpointId
 * @returns {Promise<{ status: string, delivery: string }>}
 */
export async function redeliverJoin(childEndpointId) {
  const target = _requireAdminTarget('redeliver a join decision');
  if (_useMock) {
    await mockDelay(300);
    return { status: 'redelivered', delivery: 'delivered' };
  }

  const node = _requireNode();
  const dto = await node.admin_redeliver_join(target, childEndpointId);
  try {
    return { status: 'redelivered', delivery: dto.delivery };
  } finally {
    dto.free?.();
  }
}

/**
 * Reserve a child slot without a join request.
 *
 * The web client has no `create-child` call on its wasm surface: in a live
 * network a child appears when a join request is approved (or from the node
 * CLI). Only mock mode can create one here.
 *
 * @param {number|null} slot
 * @returns {Promise<{ status: string, address: string }>}
 */
export async function createChild(slot) {
  if (_useMock) {
    await mockDelay(500);
    const s = slot ?? 5;
    return { status: 'created', address: `0.3.${s}` };
  }
  throw new Error(
    'Creating a child slot is not part of this web client: children are created by ' +
      'approving a join request (Admin → Pending joins) or from the node CLI.',
  );
}

/** Stable reject code → honest user-facing topology error copy. */
const TOPOLOGY_REJECT_MESSAGES = {
  unauthorized:
    'The node refused this action: this browser is not a designated administrator of that node.',
  slot_taken: 'That slot is taken. Pick another slot.',
  slot_out_of_range: 'That slot is out of range (must be 0-7).',
  not_found: 'That child is no longer attached to this node. Refresh and try again.',
  bad_request:
    'The node refused this topology change (browser leaves cannot be re-slotted).',
  expired: 'The request expired before it reached the node. Try again.',
  replay: 'A duplicate request was refused. Refresh and try again.',
  internal: 'The node could not apply the change (internal error).',
};

/**
 * Map a wasm `admin request rejected: <code>` error to honest topology copy.
 * @param {any} err
 * @returns {Error}
 */
function _topologyError(err) {
  const message = String(err?.message ?? err ?? '');
  const marker = 'admin request rejected: ';
  const index = message.indexOf(marker);
  const code = index >= 0 ? message.slice(index + marker.length).trim() : '';
  const friendly = TOPOLOGY_REJECT_MESSAGES[code];
  if (friendly) return new Error(friendly);
  return new Error(
    message && !message.startsWith('admin request rejected:')
      ? message
      : 'Topology action failed. Refresh and try again.',
  );
}

/**
 * Designate a child as an administrator of the current admin target. The node
 * applies it; refusals map to honest topology copy.
 *
 * @param {string} childEndpointId
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<{ status: 'designated', child: string }>}
 */
export async function adminDesignate(childEndpointId, nodeId = undefined) {
  const target = _requireAdminTarget('designate an administrator', nodeId);
  if (_useMock) {
    await mockDelay(300);
    return { status: 'designated', child: childEndpointId };
  }
  const node = _requireNode();
  try {
    await node.admin_designate(target, childEndpointId);
  } catch (err) {
    throw _topologyError(err);
  }
  return { status: 'designated', child: childEndpointId };
}

/**
 * Revoke a child's administrator designation on the current admin target.
 *
 * @param {string} childEndpointId
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<{ status: 'revoked', child: string }>}
 */
export async function adminRevoke(childEndpointId, nodeId = undefined) {
  const target = _requireAdminTarget('revoke an administrator', nodeId);
  if (_useMock) {
    await mockDelay(300);
    return { status: 'revoked', child: childEndpointId };
  }
  const node = _requireNode();
  try {
    await node.admin_revoke(target, childEndpointId);
  } catch (err) {
    throw _topologyError(err);
  }
  return { status: 'revoked', child: childEndpointId };
}

/**
 * Detach a child from the current admin target.
 *
 * The browser never holds operator/ledger keys: the node applies the change.
 * Refusals map to honest errors.
 *
 * @param {string} childEndpointId
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<{ status: 'detached', child: string }>}
 */
export async function adminDetachChild(childEndpointId, nodeId = undefined) {
  const target = _requireAdminTarget('detach a child', nodeId);
  if (_useMock) {
    await mockDelay(400);
    return { status: 'detached', child: childEndpointId };
  }
  const node = _requireNode();
  try {
    await node.admin_detach_child(target, childEndpointId);
  } catch (err) {
    throw _topologyError(err);
  }
  return { status: 'detached', child: childEndpointId };
}

/**
 * Re-slot a `node` child of the current admin target. `slot` of `null` lets
 * the node pick the lowest free slot.
 *
 * @param {string} childEndpointId
 * @param {number|null} slot
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<{ status: 'moved', child: string, slot: number|null }>}
 */
export async function adminMoveChild(childEndpointId, slot = null, nodeId = undefined) {
  const target = _requireAdminTarget('re-slot a child', nodeId);
  if (_useMock) {
    await mockDelay(500);
    return { status: 'moved', child: childEndpointId, slot: slot ?? null };
  }
  const node = _requireNode();
  try {
    await node.admin_move_child(target, childEndpointId, slot ?? null);
  } catch (err) {
    throw _topologyError(err);
  }
  return { status: 'moved', child: childEndpointId, slot: slot ?? null };
}

// ── Value administration: issue / burn ────────────────────────

/** localStorage key for the single in-flight value operation. */
export const VALUE_PENDING_KEY = STORAGE_KEYS.VALUE_PENDING;

/**
 * Whether the current admin target permits a value operation: an unlocked
 * admin mode pointed at a non-self ancestor. Pure, so it is unit-testable.
 * @param {{ isSelf?: boolean }|null|undefined} view
 * @param {{ canAdminister?: boolean }|null|undefined} caps
 * @returns {boolean}
 */
export function canAdministerValue(view, caps) {
  return Boolean(view != null && !view.isSelf && caps?.canAdminister);
}

/** Reject-code → honest user-facing value error copy. */
const VALUE_REJECT_MESSAGES = {
  insufficient_balance: 'That burn exceeds the account\u2019s current balance.',
  unauthorized:
    'The node refused this value operation: this browser is not a designated administrator of that node.',
  not_found: 'That account is no longer a child of this node. Refresh and try again.',
  bad_request:
    'The node refused this value operation (check the amount and reason).',
  expired: 'The request expired before it reached the node. Try again.',
  replay: 'A duplicate frame was refused. Check the pending operation below.',
  internal: 'The node could not apply the change (internal error).',
};

/**
 * Map an `admin request rejected: <code>` (or other) error message to honest
 * value copy. Pure, so it is unit-testable.
 * @param {string} raw
 * @returns {string}
 */
export function valueErrorMessage(raw) {
  const message = String(raw ?? '');
  const marker = 'admin request rejected: ';
  const index = message.indexOf(marker);
  const code = index >= 0 ? message.slice(index + marker.length).trim() : '';
  const friendly = VALUE_REJECT_MESSAGES[code];
  if (friendly) return friendly;
  return message && !message.startsWith(marker)
    ? message
    : 'Value operation failed. Refresh and try again.';
}

/**
 * Wrap [`valueErrorMessage`] in an `Error`.
 * @param {any} err
 * @returns {Error}
 */
function _valueError(err) {
  return new Error(valueErrorMessage(err?.message ?? err));
}

/** Resolve a localStorage-like object, or null when unavailable. */
function _persistenceStore() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) return window.localStorage;
  } catch {
    /* ignore */
  }
  try {
    if (typeof globalThis !== 'undefined' && globalThis.localStorage) return globalThis.localStorage;
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * The single in-flight value operation, or null. Persisted **before** the wasm
 * call so a reload/timeout can retry with the same idempotency key.
 * @returns {{ requestId: string, target: string, direction: 'issue'|'burn', account: string, amount: number, reason: string, at: number }|null}
 */
export function readPendingValueOp() {
  const store = _persistenceStore();
  if (!store) return null;
  let raw = null;
  try {
    raw = store.getItem(VALUE_PENDING_KEY);
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (
      parsed &&
      typeof parsed.requestId === 'string' &&
      parsed.requestId.length === 32 &&
      typeof parsed.target === 'string' &&
      (parsed.direction === 'issue' || parsed.direction === 'burn') &&
      typeof parsed.account === 'string' &&
      Number.isFinite(parsed.amount) &&
      typeof parsed.reason === 'string'
    ) {
      return parsed;
    }
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * Clear the in-flight value operation. With no `requestId`, clears it
 * unconditionally; with one, clears only when it matches.
 * @param {string} [requestId]
 */
export function clearPendingValueOp(requestId = undefined) {
  const store = _persistenceStore();
  if (!store) return;
  try {
    if (requestId != null) {
      const pending = readPendingValueOp();
      if (!pending || pending.requestId !== requestId) return;
    }
    store.removeItem(VALUE_PENDING_KEY);
  } catch {
    /* ignore */
  }
}

/** Persist the in-flight value operation (best-effort). */
function _savePendingValueOp(pending) {
  const store = _persistenceStore();
  if (!store) return;
  try {
    store.setItem(VALUE_PENDING_KEY, JSON.stringify(pending));
  } catch {
    /* ignore */
  }
}

/** A fresh 16-byte idempotency key as 32 lowercase hex characters. */
function _randomRequestId() {
  return _randomHex32().slice(0, 32);
}

/**
 * Run one value operation (issue or burn), persisting the
 * idempotency key before the call and clearing it only once the node confirms
 * the operation (applied or duplicate).
 * @param {'issue'|'burn'} direction
 * @param {string} account
 * @param {number} amount
 * @param {string} reason
 * @param {string} [nodeId]
 * @param {string} [reuseRequestId] reuse a persisted idempotency key (retry)
 */
async function _adminValue(
  direction,
  account,
  amount,
  reason,
  nodeId = undefined,
  reuseRequestId = undefined,
) {
  const target = _requireAdminTarget('issue or burn value', nodeId);

  // The value dialog validates the same conditions, but this is the hard
  // boundary: the wasm calls take the amount as an `i64`/`bigint`, so a
  // fractional or non-positive JS number must be refused here — passing a plain
  // `Number` would throw `TypeError: Cannot convert … to a BigInt` before any
  // network call, and the mock short-circuit below would hide it.
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new RangeError('Amount must be a positive whole number.');
  }
  const wasmAmount = BigInt(amount);

  if (_useMock) {
    await mockDelay(500);
    const requestId = reuseRequestId ?? _randomRequestId();
    _savePendingValueOp({ requestId, target, direction, account, amount, reason, at: Date.now() });
    clearPendingValueOp(requestId);
    return {
      status: 'applied',
      requestId,
      account,
      direction,
      amount,
      balanceAfter: amount,
      seq: 1,
      entryHash: '00'.repeat(32),
      duplicate: false,
    };
  }

  if (!canAdministerValue(administeredNode, adminCapabilities)) {
    throw new AdminUnavailableError('admin value operation');
  }

  const node = _requireNode();
  const requestId = reuseRequestId ?? _randomRequestId();
  const pending = {
    requestId,
    target,
    direction,
    account,
    amount,
    reason,
    at: Date.now(),
  };

  // Persist BEFORE sending so a reload/timeout retries the same logical op.
  _savePendingValueOp(pending);
  try {
    const dto =
      direction === 'issue'
        ? await node.admin_issue(target, requestId, account, wasmAmount, reason)
        : await node.admin_burn(target, requestId, account, wasmAmount, reason);
    const result = {
      status: dto.duplicate ? 'duplicate' : 'applied',
      requestId: dto.request_id,
      account: dto.account,
      direction: dto.direction,
      amount: dto.amount,
      balanceAfter: dto.balance_after,
      seq: dto.seq,
      entryHash: dto.entry_hash,
      duplicate: dto.duplicate,
    };
    try {
      dto.free?.();
    } finally {
      // Clear only after the node confirmed the operation.
      clearPendingValueOp(requestId);
    }
    return result;
  } catch (err) {
    // Keep the pending record so the UI can Retry / Discard.
    throw _valueError(err);
  }
}

/**
 * Issue `amount` into `account` on the administered node (value scope).
 * @param {string} account
 * @param {number} amount
 * @param {string} reason
 * @param {string} [nodeId]
 */
export async function adminIssue(account, amount, reason, nodeId = undefined) {
  return _adminValue('issue', account, amount, reason, nodeId);
}

/**
 * Burn `amount` from `account` on the administered node (value scope).
 * @param {string} account
 * @param {number} amount
 * @param {string} reason
 * @param {string} [nodeId]
 */
export async function adminBurn(account, amount, reason, nodeId = undefined) {
  return _adminValue('burn', account, amount, reason, nodeId);
}

/**
 * Retry the persisted in-flight value operation (if any) against the current
 * selection. On success the pending record is cleared; on failure it is kept.
 * @returns {Promise<object|null>}
 */
export async function retryPendingValueOp() {
  const pending = readPendingValueOp();
  if (!pending) return null;
  const result = await _adminValue(
    pending.direction,
    pending.account,
    pending.amount,
    pending.reason,
    pending.target,
    pending.requestId,
  );
  return result;
}

/**
 * Leave the current parent network.
 *
 * Live mode calls the wasm client's `leave()`: it signs an `ExitRequest`,
 * best-effort delivers it to the current parent over `cawala/control/0`, then
 * clears the local parent and address **regardless of the reply** — so an
 * unreachable or refusing parent cannot trap the user. The returned `delivery`
 * is the former parent's reply bucket (`accepted` / `rejected:<code>` /
 * `unreachable`) and is diagnostic only; `status` is always `detached`.
 *
 * The wasm client also queues a `detached` control event, surfaced through the
 * existing drain (`getLastControlEvent()`), which clears the mirrored join
 * address so the UI can show "Left network".
 *
 * Mock mode keeps a plausible fake result.
 *
 * @returns {Promise<{ status: string, delivery?: string }>}
 */
export async function leave() {
  if (_useMock) {
    await mockDelay(400);
    return { status: 'detached' };
  }

  const node = _requireNode();
  if (typeof node.leave !== 'function') {
    throw new Error('This client build does not support leaving the network.');
  }

  let outcome;
  try {
    outcome = await node.leave();
  } catch (err) {
    throw new Error(`Leave failed: ${_errorMessage(err)}`);
  }

  try {
    const result = {
      status: outcome.status,
      delivery: outcome.delivery ?? null,
    };
    // The local wasm state is now parentless: mirror and persist immediately
    // (the poller would also pick this up on its next tick). The wasm `leave()`
    // cleared the parent-scoped ledger binding, so persist the ledger blob
    // before the state blob and resync the reactive store.
    _syncJoinStateIntoStore();
    _syncConnectionStatusIntoStore();
    _persistLedgerState();
    _syncLedgerStoreFromStatus();
    _persistState();
    return result;
  } finally {
    outcome.free?.();
  }
}

/**
 * Issue or burn value against an account.
 * @param {string} accountAddress
 * @param {number} amount - Positive = issue, negative = burn.
 * @param {string} reason
 * @returns {Promise<{ status: string, newBalance: number }>}
 */
export async function issueBurn(accountAddress, amount, reason) {
  if (_useMock) {
    await mockDelay(400);
    // Find the mock account and adjust
    const acct = MOCK_DATA.accounts.find((a) => a.address === accountAddress);
    const newBalance = (acct ? acct.balance : 0) + amount;
    return { status: amount > 0 ? 'issued' : 'burned', newBalance };
  }
  throw new Error('Not implemented: real issueBurn');
}

// ── Invite parsing ────────────────────────────────────────────

/**
 * Parse and validate a Cawala invite code/URI using the live wasm parser.
 *
 * Accepted formats (live):
 *   - Full URI: cawala://join?parent=<EndpointId>&op=<64-hex>[&slot=<0..7>][&exp=<unix>][&label=<pct>][&relay=<url>][&ip=<host:port>]
 *     (bare base64 is NOT a real format and is rejected in live mode; the mock
 *     parser still accepts it so existing mock UI flows keep working.)
 *
 * @param {string} code - Raw invite string from the user.
 * @returns {Promise<{ parent: string, operator: string, slot?: number, expiry?: number, label?: string, relay?: string, ip?: string, raw: string }>}
 * @throws {Error} With a user-facing message if the invite is invalid.
 */
export async function parseInvite(code) {
  const trimmed = (code || '').trim();
  if (!trimmed) {
    throw new Error('Paste an invite code or link from a node operator.');
  }

  if (_useMock) {
    await mockDelay(150);
    return _mockParseInvite(trimmed);
  }

  if (!_wasmModule) {
    throw new Error('Invite parsing is unavailable: the wasm client is not loaded.');
  }

  let info;
  try {
    info = _wasmModule.parse_invite(trimmed);
  } catch (err) {
    throw new Error(`Invalid invite: ${err?.message ?? err}`);
  }

  try {
    const result = {
      parent: info.parent,
      operator: info.operator,
      raw: trimmed,
    };
    if (info.slot !== undefined) result.slot = info.slot;
    if (info.expiry !== undefined) result.expiry = info.expiry;
    if (info.label !== undefined) result.label = info.label;
    if (info.relay !== undefined) result.relay = info.relay;
    if (info.ip !== undefined) result.ip = info.ip;
    return result;
  } finally {
    info.free?.();
  }
}

/**
 * Mock invite parser. Recognises:
 *   - cawala://join?parent=...&op=... (valid)
 *   - Anything else that looks vaguely like base64 (valid with defaults)
 *   - Empty / garbage → throws
 */
function _mockParseInvite(raw) {
  // Try URI format first
  try {
    const url = new URL(raw);
    if (url.protocol === 'cawala:' && url.host === 'join') {
      const parent = url.searchParams.get('parent');
      const op = url.searchParams.get('op');
      if (!parent || !op) {
        throw new Error('Invite is missing required fields (parent, operator key).');
      }
      if (!/^[0-9a-fA-F]{64}$/.test(op)) {
        throw new Error('Operator key must be 64 hex characters.');
      }
      const slotRaw = url.searchParams.get('slot');
      const expRaw = url.searchParams.get('exp');
      const labelRaw = url.searchParams.get('label');
      const relayRaw = url.searchParams.get('relay');
      const ipRaw = url.searchParams.get('ip');
      const result = {
        parent,
        operator: op,
        raw,
      };
      if (slotRaw != null) {
        const slot = Number(slotRaw);
        if (!Number.isInteger(slot) || slot < 0 || slot > 7) {
          throw new Error('Slot must be an integer between 0 and 7.');
        }
        result.slot = slot;
      }
      if (expRaw != null) {
        const exp = Number(expRaw);
        if (!Number.isFinite(exp) || exp <= 0) {
          throw new Error('Expiry must be a valid unix timestamp.');
        }
        result.expiry = exp;
      }
      if (labelRaw) {
        result.label = decodeURIComponent(labelRaw);
      }
      if (relayRaw) {
        const relay = decodeURIComponent(relayRaw);
        // Must have a scheme and host — reject bare strings
        try {
          const parsed = new URL(relay);
          if (!parsed.protocol || !parsed.host) {
            throw new Error();
          }
        } catch {
          throw new Error('Relay must be a valid URL (e.g. https://relay.example.com).');
        }
        result.relay = relay;
      }
      if (ipRaw) {
        // Validate host:port format — reject empty host, missing port, non-numeric port
        const colonIdx = ipRaw.lastIndexOf(':');
        if (colonIdx <= 0 || colonIdx === ipRaw.length - 1) {
          throw new Error('IP must be in host:port format (e.g. 192.168.1.1:4433).');
        }
        const host = ipRaw.slice(0, colonIdx);
        const portStr = ipRaw.slice(colonIdx + 1);
        const port = Number(portStr);
        if (!host || !/^\d{1,5}$/.test(portStr) || !Number.isInteger(port) || port < 1 || port > 65535) {
          throw new Error('IP must be in host:port format with a valid port (e.g. 192.168.1.1:4433).');
        }
        result.ip = ipRaw;
      }
      return result;
    }
  } catch (e) {
    // If it was a URL parse error or a validation error we threw, re-throw validation errors
    if (e.message && !e.message.includes('Invalid URL')) {
      throw e;
    }
  }

  // Try bare base64url JSON
  try {
    const padded = raw.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(padded);
    const obj = JSON.parse(json);
    if (obj.parent && obj.op) {
      const result = { parent: obj.parent, operator: obj.op, raw };
      if (obj.slot != null) result.slot = obj.slot;
      if (obj.exp != null) result.expiry = obj.exp;
      if (obj.label) result.label = obj.label;
      if (obj.relay) result.relay = obj.relay;
      if (obj.ip) result.ip = obj.ip;
      return result;
    }
    throw new Error('Invite is missing required fields (parent, operator key).');
  } catch (e) {
    if (e.message && e.message.includes('missing required')) {
      throw e;
    }
  }

  // Nothing worked
  throw new Error("That doesn't look like a cawala invite. Ask the node operator to send a fresh one.");
}

// ── Data fetching ─────────────────────────────────────────────

/**
 * Get the children of the current admin target.
 *
 * - mock: the synthetic child list (mock is a data source, not a layout).
 * - `self`: this browser's own local topology snapshot.
 * - an ancestor: its `AdminQuery` topology snapshot.
 *
 * Each row carries `kind` (`node` | `user`) so the UI can infer the target's
 * node kind; `balance` is always null here — balances are never fabricated.
 *
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<Array>}
 */
export async function getChildren(nodeId = undefined) {
  const target = _normalizeTarget(nodeId);

  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.children];
  }

  if (target === SELF || target === clientState.endpointId) {
    return _readLocalChildren();
  }
  // Locked mode hides ancestor state without marking the target unreachable.
  if (!adminLock.unlocked) return [];

  try {
    const data = await _queryAdminSnapshot(target);
    _recordQueryOutcome(target, { ok: true, kind: inferNodeKind(data.children), address: data.address });
    return data.children;
  } catch (err) {
    _recordQueryOutcome(target, { ok: false, error: err });
    _warnOnce(`admin-query-children:${target}`, '[api] admin_query (children) failed', err);
    return [];
  }
}

/**
 * Get the current admin target's designated administrator child ids.
 *
 * The node reports the set in its `AdminQuery` reply (`AdminSnapshot.admins`),
 * so this is the authoritative "who currently administers this node" list — not
 * a guess from the child list.
 *
 * - mock: the synthetic designation set.
 * - `self`: this browser's own leaf has no children and therefore no set → `[]`.
 * - an ancestor: the `admins` field of its `AdminQuery` reply.
 * Locked mode yields `[]` without marking the target unreachable.
 *
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<Array<string>>}
 */
export async function getAdministrators(nodeId = undefined) {
  const target = _normalizeTarget(nodeId);

  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.admins];
  }

  if (target === SELF || target === clientState.endpointId) return [];
  // Locked mode hides ancestor state without marking the target unreachable.
  if (!adminLock.unlocked) return [];

  try {
    const data = await _queryAdminSnapshot(target);
    _recordQueryOutcome(target, { ok: true, kind: inferNodeKind(data.children), address: data.address });
    return data.admins;
  } catch (err) {
    _recordQueryOutcome(target, { ok: false, error: err });
    _warnOnce(`admin-query-admins:${target}`, '[api] admin_query (admins) failed', err);
    return [];
  }
}

/**
 * Record what an admin query saw about a target (status/kind/address) and
 * refresh the stored view. Failures mark the target unreachable rather than
 * dropping the last observed kind.
 * @param {string} target
 * @param {{ ok: boolean, kind?: string, address?: string|null, error?: any }} outcome
 */
function _recordQueryOutcome(target, outcome) {
  if (target === SELF || target === clientState.endpointId) {
    if (outcome.kind) {
      _selfKind = outcome.kind;
      _syncAdministeredNode();
    }
    return;
  }
  _recordTargetProbe(target, outcome);
}

/**
 * The mock accounts with the derived equity appended.
 *
 * Equity is never posted: it is `Parent − ΣChild`. Compute the mock "equity"
 * figure from the asset/liability rows rather than storing an equity balance,
 * matching the no-Equity ledger model.
 * @param {Array} accounts
 * @returns {Array}
 */
function withDerivedEquity(accounts) {
  const total = (type) =>
    accounts
      .filter((a) => a.type === type)
      .reduce((sum, a) => sum + (a.balance ?? 0), 0);
  const asset = accounts.find((a) => a.type === 'asset');
  return [
    ...accounts,
    {
      address: asset?.address ?? '0.3',
      type: 'equity',
      label: 'Node equity',
      balance: total('asset') - total('liability'),
    },
  ];
}

/**
 * Whether the current admin target permits a ledger read: an unlocked admin
 * mode pointed at a non-self ancestor. Pure, so it is unit-testable.
 * @param {{ canAdminister?: boolean }|null|undefined} caps
 * @returns {boolean}
 */
export function canReadAdminLedger(caps) {
  return Boolean(caps?.canAdminister);
}

/**
 * Whether the admin surface permits topology/designation actions: an unlocked
 * admin mode pointed at a **non-self** target. Pure, so it is unit-testable.
 * @param {{ isSelf?: boolean }|null|undefined} view
 * @param {{ canAdminister?: boolean }|null|undefined} caps
 * @returns {boolean}
 */
export function canAdministerTopology(view, caps) {
  return Boolean(view != null && !view.isSelf && caps?.canAdminister);
}

/**
 * Whether a child of the given `kind` can be re-slotted: only a `node` child
 * has a healing pull. A `user` (browser leaf) child cannot be re-slotted.
 * Pure, so it is unit-testable.
 * @param {string|null|undefined} kind
 * @returns {boolean}
 */
export function canMoveChild(kind) {
  return kind === 'node';
}

/**
 * Map a plain admin-ledger snapshot to the account-row shape the Accounts page
 * renders: one parent-asset row from `parentBalance`, one liability row per
 * account (with its kind/address when the node reported them), then the
 * canonical equity row. `equity` comes straight from the node (`Parent −
 * ΣChild`) and is never re-derived here.
 *
 * The returned array carries a `truncated` flag (attached as a property) so a
 * caller can surface the node's row cap without changing the row shape.
 *
 * @param {{ parentBalance?: number, equity?: number, root?: boolean, truncated?: boolean, accounts?: Array<{ id: string, kind?: string|null, slot?: number|null, address?: string|null, balance?: number }> }} snapshot
 * @returns {Array<object>}
 */
export function mapAdminLedgerRows(snapshot) {
  const rows = [
    {
      id: null,
      address: null,
      type: 'asset',
      kind: null,
      label: snapshot.root ? 'Detached parent balance' : 'Account with parent',
      balance: Number(snapshot.parentBalance ?? 0),
    },
  ];
  for (const account of snapshot.accounts ?? []) {
    const address = account.address ?? null;
    rows.push({
      id: account.id,
      address,
      type: 'liability',
      kind: account.kind ?? null,
      slot: account.slot ?? null,
      label: address ? `Account for ${address}` : `Account for ${account.id}`,
      balance: Number(account.balance ?? 0),
    });
  }
  rows.push({
    id: null,
    address: null,
    type: 'equity',
    kind: null,
    label: 'Node equity',
    balance: Number(snapshot.equity ?? 0),
  });
  rows.truncated = Boolean(snapshot.truncated);
  return rows;
}

/**
 * Get accounts for the current admin target.
 *
 * - mock: the synthetic accounting rows (with derived equity).
 * - `self`: this browser's verified balance, only once a receipt exists (the
 *   cryptographically verified leaf path).
 * - an ancestor: the node's own read-only accounting snapshot
 *   (`AdminLedgerQuery`), mapped to the same row shape. Admin mode must be
 *   unlocked; otherwise `[]`. Balances are node-asserted and never fabricated.
 *
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<Array>}
 */
export async function getAccounts(nodeId = undefined) {
  const target = _normalizeTarget(nodeId);

  if (_useMock) {
    await mockDelay(200);
    return withDerivedEquity(MOCK_DATA.accounts);
  }

  // This browser's own node keeps the cryptographically verified balance path.
  if (target === SELF || target === clientState.endpointId) {
    const address = getAddress();
    if (!address || ledgerState.balance == null) return [];
    return [
      {
        address,
        type: 'asset',
        label: 'My account',
        balance: ledgerState.balance,
      },
    ];
  }

  // An ancestor's books are only readable once admin mode is unlocked.
  if (!canReadAdminLedger(adminCapabilities)) return [];

  try {
    const snapshot = await _queryAdminLedger(target);
    const rows = mapAdminLedgerRows(snapshot);
    const children = snapshot.accounts
      .filter((row) => row.kind)
      .map((row) => ({ kind: row.kind }));
    _recordQueryOutcome(target, {
      ok: true,
      kind: inferNodeKind(children),
      address: _adminTargets.find((t) => t.node.toLowerCase() === target)?.address ?? null,
    });
    return rows;
  } catch (err) {
    _recordQueryOutcome(target, { ok: false, error: err });
    _warnOnce(`admin-ledger:${target}`, '[api] admin_ledger_query failed', err);
    return [];
  }
}

/**
 * Run one admin ledger query (direct first, routed fallback inside the wasm
 * `admin_ledger_query`) and read the reply into a plain snapshot object.
 * @param {string} target
 * @returns {Promise<object>}
 */
async function _queryAdminLedger(target) {
  const node = _requireNode();
  const snapshot = await node.admin_ledger_query(target);
  return _readAdminLedgerSnapshot(snapshot);
}

/**
 * Copy an `AdminLedgerSnapshotDto` to plain data and free every wasm handle it
 * created (account rows and the snapshot). Handles are read once and freed once.
 * @param {object} snapshot
 * @returns {object}
 */
function _readAdminLedgerSnapshot(snapshot) {
  let accounts = [];
  try {
    accounts = snapshot.accounts ?? [];
    return {
      nodeId: snapshot.node_id ?? null,
      ledgerId: snapshot.ledger_id ?? null,
      height: snapshot.height ?? 0,
      parentBalance: snapshot.parent_balance ?? 0,
      equity: snapshot.equity ?? 0,
      root: Boolean(snapshot.root),
      truncated: Boolean(snapshot.truncated),
      accounts: accounts.map((row) => ({
        id: row.id,
        kind: row.kind ?? null,
        slot: row.slot ?? null,
        address: row.address ?? null,
        balance: row.balance ?? 0,
      })),
    };
  } finally {
    for (const row of accounts) row.free?.();
    snapshot.free?.();
  }
}

/**
 * Get pending join requests for the current admin target.
 *
 * Live mode needs admin mode unlocked (mock always has data). A locked mode or
 * this browser's own leaf yields `[]` — the page decides which empty state to
 * show from `adminCapabilities`. An unreachable target records `unreachable`
 * so the context bar can say so.
 *
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<Array>}
 */
export async function getJoinRequests(nodeId = undefined) {
  const target = _normalizeTarget(nodeId);
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.joinRequests];
  }

  // A browser leaf has no pending joins, and nothing is queryable while locked.
  if (target === SELF || target === clientState.endpointId || !adminLock.unlocked) return [];

  try {
    const data = await _queryAdminSnapshot(target);
    _recordQueryOutcome(target, { ok: true, kind: inferNodeKind(data.children), address: data.address });
    return data.pendingRows.map((row) => ({
      endpointId: row.endpointId,
      requestedAddress: null,
      slot: row.slot,
      kind: row.kind,
      operator: row.operator,
      expiry: row.expiry,
      timestamp: null,
      status: 'pending',
      nodeId: target,
    }));
  } catch (err) {
    _recordQueryOutcome(target, { ok: false, error: err });
    _warnOnce(`admin-query-joins:${target}`, '[api] admin_query (joins) failed', err);
    return [];
  }
}

/**
 * Normalize a ledger activity entry into the shared table row shape.
 * @param {object} entry
 */
function _mapActivityEntry(entry) {
  const isSettlement = entry.type === ACTIVITY_TYPES.SETTLEMENT;
  return {
    id: entry.id,
    type: entry.type,
    label: ACTIVITY_LABELS[entry.type] || entry.type,
    from: entry.from,
    to: entry.to,
    amount: entry.amount,
    timestamp: entry.timestamp,
    reported: true,
    status: isSettlement ? entry.status : (entry.status ?? null),
    reason: isSettlement ? entry.reason : (entry.reason ?? null),
    failedAt: isSettlement ? (entry.failedAt ?? null) : null,
    orderHash: isSettlement ? entry.orderHash : (entry.orderHash ?? null),
  };
}

/**
 * Get activity log entries for the current admin target.
 *
 * - mock: the synthetic log.
 * - `this browser's leaf`: the locally reported payment/settlement history.
 * - an ancestor: `[]` — an ancestor's activity log does not exist in this
 *   phase, and this browser's own payments must not be shown under another
 *   node's name.
 *
 * @param {object} [filters]
 * @param {string} [filters.type]
 * @param {string} [filters.address]
 * @param {string} [nodeId] Target; defaults to the current admin target.
 * @returns {Promise<Array>}
 */
export async function getActivityLog(filters, nodeId = undefined) {
  const target = _normalizeTarget(nodeId);

  if (_useMock) {
    await mockDelay(200);
    let entries = [...MOCK_DATA.activity];
    if (filters?.type) entries = entries.filter((e) => e.type === filters.type);
    if (filters?.address) {
      const addr = filters.address.toLowerCase();
      entries = entries.filter(
        (e) =>
          (e.from && e.from.toLowerCase().includes(addr)) ||
          (e.to && e.to.toLowerCase().includes(addr)),
      );
    }
    return entries;
  }

  if (target !== SELF && target !== clientState.endpointId) return [];

  // UI-shaped entries accumulated by the ledger-event poller, newest first.
  let entries = ledgerState.activity.map(_mapActivityEntry);
  entries.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  if (filters?.type) entries = entries.filter((e) => e.type === filters.type);
  if (filters?.address) {
    const addr = filters.address.toLowerCase();
    entries = entries.filter(
      (e) =>
        (e.from && e.from.toLowerCase().includes(addr)) ||
        (e.to && e.to.toLowerCase().includes(addr)),
    );
  }
  return entries;
}

/**
 * Live join-handshake status.
 *
 * `rejectCode` is the stable machine code of the last rejection
 * (`JoinStatus.reject_code`), distinct from the human-readable `reason`. When a
 * join is outstanding, `pendingJoin` carries the full outbound request
 * (`pending_join_outbound()`).
 *
 * @returns {{ state: string, parent: string|null, slot: number|null, address: string|null, reason: string|null, rejectCode: string|null, pendingJoin: object|null }}
 */
export function getJoinStatus() {
  if (_useMock) {
    return {
      state: JOIN_STATE.JOINED,
      parent: null,
      slot: null,
      address: '0.3.1',
      reason: null,
      rejectCode: null,
      pendingJoin: null,
    };
  }
  if (!_clientNode) {
    return {
      state: JOIN_STATE.NONE,
      parent: null,
      slot: null,
      address: null,
      reason: null,
      rejectCode: null,
      pendingJoin: null,
    };
  }
  return {
    ..._readJoinStatus(_clientNode),
    pendingJoin: _readPendingJoinOutbound(_clientNode),
  };
}

/**
 * Copy a wasm `JoinStatus` DTO to a plain object and free it.
 * @param {object} node
 * @returns {{ state: string, parent: string|null, slot: number|null, address: string|null, reason: string|null, rejectCode: string|null }}
 */
function _readJoinStatus(node) {
  const status = node.join_status();
  try {
    return {
      state: status.state,
      parent: status.parent ?? null,
      slot: status.slot ?? null,
      address: status.address ?? null,
      reason: status.reason ?? null,
      rejectCode: status.reject_code ?? null,
    };
  } finally {
    status.free?.();
  }
}

/**
 * Describe what this client can do right now.
 * @returns {{ mock: boolean, canAdmin: boolean, canQueryPeers: boolean, identityPersistent: boolean, multiTabLeader: boolean, multiTabWarning: string|null }}
 */
export function getCapabilities() {
  return _capabilityView(_deriveAdminView().caps);
}

/**
 * Look up a suggested address by location. Not available in the web client.
 * @param {number} lat
 * @param {number} lon
 * @returns {Promise<string|null>}
 */
export async function lookupAddressByLocation(lat, lon) {
  if (_useMock) {
    await mockDelay(400);
    // Mock: return a plausible address based on rough region
    return '0.3';
  }
  throw new Error(
    'Address lookup by location is not available in the web client yet. ' +
      'Use the node operator CLI to derive an address.',
  );
}

// ── Hex / base64 helpers ──────────────────────────────────────

/**
 * @param {Uint8Array} bytes
 * @returns {string} lowercase hex
 */
function _bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * @param {string} hex
 * @returns {Uint8Array}
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
 * @returns {string} base64
 */
function _bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * A user-facing message from a wasm/JsError or any thrown value.
 * @param {unknown} err
 * @returns {string}
 */
function _errorMessage(err) {
  if (err == null) return 'unknown error';
  if (typeof err === 'string') return err;
  if (typeof err.message === 'string' && err.message) return err.message;
  return String(err);
}

/**
 * 32 random bytes as 64 lowercase hex chars (mock order-hash stand-in).
 * @returns {string}
 */
function _randomHex32() {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return _bytesToHex(bytes);
}

// ── Mock data ─────────────────────────────────────────────────

const MOCK_DATA = {
  children: [
    {
      address: '0.3.1',
      endpointId: 'z6MkHs7Kj3xVnR5pQw9bYf2dLg8mC4tEa6uIiOoPp',
      balance: 1200,
      seniority: '2025-01-15T00:00:00Z',
      online: true,
      slot: 1,
      kind: 'node',
    },
    {
      address: '0.3.2',
      endpointId: 'z6MkRt5nYh7kJf3gWp2xDs9cVq6bLm4eAf8uOiIiPpOo',
      balance: 800,
      seniority: '2025-03-22T00:00:00Z',
      online: false,
      slot: 2,
      kind: 'node',
    },
    {
      address: '0.3.3',
      endpointId: 'z6MkBu4iNk8mHj2fXs7cWr5eVq3dLp9gAj6uOiIiPpOo',
      balance: 2100,
      seniority: '2024-11-08T00:00:00Z',
      online: true,
      slot: 3,
      kind: 'node',
    },
  ],
  accounts: [
    // Liability accounts (held for children)
    {
      address: '0.3.1',
      type: 'liability',
      label: 'Account for 0.3.1',
      balance: 1200,
    },
    {
      address: '0.3.2',
      type: 'liability',
      label: 'Account for 0.3.2',
      balance: 800,
    },
    {
      address: '0.3.3',
      type: 'liability',
      label: 'Account for 0.3.3',
      balance: 2100,
    },
    // Asset account (with parent)
    {
      address: '0.3',
      type: 'asset',
      label: 'Account with parent 0.3',
      balance: 4500,
    },
  ],
  joinRequests: [
    {
      endpointId: 'z6MkPq8rSt2nWk5jHf9cXm3dLg7bVq4eAf6uOiIiPpOo',
      requestedAddress: null,
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      status: 'pending',
    },
    {
      endpointId: 'z6MkDf6gHj3kLm8nBc4vXs2rWq5eTy9iAp7uOiIiPpOo',
      requestedAddress: '0.3.7',
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      status: 'pending',
    },
  ],
  // The synthetic designation set: the slot-1 child currently administers the
  // mock target. Mirrors the node's persisted `admin_state.json` admins list.
  admins: ['z6MkHs7Kj3xVnR5pQw9bYf2dLg8mC4tEa6uIiOoPp'],
  activity: [
    {
      id: 'a1',
      type: ACTIVITY_TYPES.TRANSFER,
      from: '0.3.1',
      to: '0.3.2',
      amount: 150,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 1800000).toISOString(),
    },
    {
      id: 'a2',
      type: ACTIVITY_TYPES.ISSUE,
      from: null,
      to: '0.3.1',
      amount: 500,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 86400000).toISOString(),
    },
    {
      id: 'a3',
      type: ACTIVITY_TYPES.JOIN_APPROVED,
      from: null,
      to: '0.3.3',
      amount: null,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 172800000).toISOString(),
    },
    {
      id: 'a4',
      type: ACTIVITY_TYPES.TOPO_CREATE,
      from: null,
      to: '0.3.2',
      amount: null,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 259200000).toISOString(),
    },
    {
      id: 'a5',
      type: ACTIVITY_TYPES.TRANSFER,
      from: '0.3.3',
      to: '0.3.1',
      amount: 300,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 345600000).toISOString(),
    },
  ],
};

// ── Mock helpers ──────────────────────────────────────────────

/**
 * Simulate network delay.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function mockDelay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
