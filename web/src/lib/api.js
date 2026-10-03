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
 *   - Live support is limited to: stable identity, invite parsing, the join
 *     handshake, ping, and a local topology snapshot. Admin actions
 *     (approve/reject), pending joins, accounts, and activity are NOT exposed
 *     by the protocol/web client and degrade gracefully (typed error / empty).
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
  applyAdministeredNode,
  applyAdminCapabilities,
  resetDataState,
  bumpTargetEpoch,
} from './stores.svelte.js';
import { NODE_KIND, inferNodeKind } from './nodeKind.js';
import * as idb from './identityBundle.js';
import * as adminKeys from './adminKeys.js';
import * as parentLiveness from './parentLiveness.js';

// ── Internal state ────────────────────────────────────────────

let _useMock = true;
let _wasmModule = null;
let _clientNode = null;

// Identity/state storage keys.
// The identity seed stays global (one browser install == one identity). The
// state/ledger blobs are identity-scoped: `${STATE_KEY}:<nodeId>`. The
// un-suffixed keys are the legacy (pre-portability) locations and are read once
// as a backward-compat fallback on load.
const IDENTITY_KEY = 'cawala.identity.v1';
const STATE_KEY = 'cawala.state.v1';
// Distinct key for the secret-free ledger blob (balance/activity/pending).
const LEDGER_KEY = 'cawala.ledger.v1';
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

// Control-event poller + last drained event.
let _controlPoller = null;
let _lastControlEvent = null;

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

// ── Initialization ────────────────────────────────────────────

/**
 * Initialize the API layer.
 *
 * `?mock` forces mock mode. Otherwise this dynamically imports the wasm
 * client, restores/generates the stable identity, spawns the control node, and
 * flips `_useMock` off. On ANY failure it falls back to mock data.
 */
export async function initApi() {
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

    // Best-effort single-leader guard: avoid binding two live endpoints with
    // the same endpoint id from concurrent tabs.
    const isLeader = await _acquireIdentityLock();
    if (!isLeader) {
      _useMock = true;
      return;
    }

    await _spawnRealNode();
    _useMock = false;
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
 * throws (Safari private mode / quota).
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
        return bytes;
      }
      _warnOnce('identity-len', '[api] stored identity has the wrong length; generating a new one');
    } catch (err) {
      _warnOnce('identity-malformed', '[api] stored identity is malformed; generating a new one', err);
    }
  }

  // Reuse the in-session fallback if we already generated one.
  if (_memorySeed) return _memorySeed;

  const seed = wasm.generate_secret_key(); // may throw → initApi falls back to mock
  _memorySeed = seed;

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
 * @param {string} base
 * @param {string} nodeId
 * @param {string} warnKey
 * @returns {Uint8Array|null}
 */
function _loadScopedBlob(base, nodeId, warnKey) {
  let b64 = null;
  try {
    b64 = window.localStorage.getItem(_scopedKey(base, nodeId));
    if (b64 == null) {
      // One-time backward compat: pre-portability installs stored the blob
      // under the un-suffixed key.
      b64 = window.localStorage.getItem(base);
    }
  } catch (err) {
    _warnOnce(warnKey, `[api] localStorage unavailable for ${base} read`, err);
    return null;
  }
  if (!b64) return null;
  try {
    return _base64ToBytes(b64);
  } catch (err) {
    _warnOnce(`${warnKey}-decode`, `[api] persisted ${base} is malformed; ignoring it`, err);
    return null;
  }
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
 * Spawn the real control client, restore state, and start the event poller.
 * @returns {Promise<import('../wasm/cawala_client.js').ClientNode>}
 */
async function _spawnRealNode() {
  const seed = _loadOrCreateIdentity(_wasmModule);
  const node = await _wasmModule.ClientNode.spawn_control(seed);
  const nodeId = node.endpoint_id();

  const stateBytes = _loadState(nodeId);
  if (stateBytes) {
    try {
      node.import_state(stateBytes);
    } catch (err) {
      console.warn('[api] import_state failed; starting from a fresh local state', err);
    }
  }

  const ledgerBytes = _loadLedgerState(nodeId);
  if (ledgerBytes) {
    try {
      node.import_ledger_state(ledgerBytes);
    } catch (err) {
      console.warn('[api] import_ledger_state failed; starting from a fresh ledger state', err);
    }
  }

  // Rebuild the UI activity list from the restored state (persisted value
  // notices + terminal settlement records) so past activity survives a reload.
  _rebuildActivityFromState(node);

  // Restore any persisted delegated admin key (K_admin) into the fresh node so
  // admin actions survive a reload. The seed is read only via adminSeedBytes.
  const activeAdmin = adminKeys.activeAdminNode();
  if (activeAdmin) {
    const adminSeed = adminKeys.adminSeedBytes(activeAdmin.nodeId);
    if (adminSeed && adminSeed.length === 32) {
      try {
        node.set_admin_key(adminSeed);
      } catch (err) {
        console.warn('[api] set_admin_key failed; admin actions will be unavailable', err);
      }
    }
  }

  _clientNode = node;
  _persistState();
  _persistLedgerState();
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

// ── Administered node (the selected admin target) ─────────────

/** Selection value for this browser's own node (see adminKeys). */
const SELF = adminKeys.SELF_SELECTION;
/** Selection value of the synthetic node shown in mock mode. */
const MOCK_NODE_ID = 'mock';

/**
 * Last node kind inferred for this browser's own node from its local
 * topology snapshot. Session-only: a local snapshot read, not a persisted claim.
 */
let _selfKind = NODE_KIND.UNKNOWN;

/**
 * Resolve the target of an admin call: an explicit id, else the persisted
 * selection, else `self`.
 * @param {string} [nodeId]
 * @returns {string}
 */
function _normalizeTarget(nodeId) {
  if (nodeId == null) return adminKeys.selectedNodeId() ?? SELF;
  return String(nodeId).toLowerCase();
}

/**
 * The stored grant that authorizes admin calls on `target`, or null.
 * For `self` that is a grant over this browser's own node id (usually none).
 * @param {string} target
 * @returns {object|null}
 */
function _grantFor(target) {
  if (target === SELF) {
    const own = clientState.endpointId;
    return own ? adminKeys.findAdminNode(own) : null;
  }
  if (target === MOCK_NODE_ID) return null;
  return adminKeys.findAdminNode(target);
}

/**
 * Derive the admin view + capability flags for the current selection.
 * Pure read: never probes the network and never invents a kind or address.
 * @returns {{ view: object, caps: object }}
 */
function _deriveAdminView() {
  const mock = _useMock;
  const target = _normalizeTarget();
  const isSelf = target === SELF;
  const isMockNode = target === MOCK_NODE_ID;
  const now = Date.now();

  const grant = _grantFor(target);
  const expired = grant ? grant.expiresAt <= now : false;

  let status;
  if (mock) status = 'mock';
  else if (!grant) status = isSelf ? 'self' : 'no-grant';
  else if (expired) status = 'expired';
  else if (grant.lastSeenStatus === 'unreachable') status = 'unreachable';
  else status = 'active';

  const kind = isMockNode
    ? inferNodeKind(MOCK_DATA.children)
    : isSelf
      ? _selfKind
      : grant?.lastSeenKind ?? NODE_KIND.UNKNOWN;

  const address = isMockNode
    ? '0.3'
    : isSelf
      ? clientState.address ?? null
      : grant?.lastSeenAddress ?? null;

  const scopes = grant ? [...grant.scopes] : [];
  const canQuery = mock || isSelf || (!!grant && !expired);
  const canAdminister = mock || (!!grant && !expired && grant.scopes.includes('joins'));

  return {
    view: {
      nodeId: target,
      isSelf,
      label: isMockNode ? 'Mock node' : isSelf ? 'This browser' : grant?.label ?? null,
      nodeAddr: grant?.nodeAddr ?? (isMockNode ? '0.3' : null),
      scopes,
      // `bundle` means the scopes/TTL came from a node-operator-signed bundle;
      // `manual` is a locally generated provisional grant. `null` for self/mock.
      grantSource: grant?.grantSource ?? null,
      grantExpiresAt: grant?.expiresAt ?? null,
      kind,
      status,
      address,
      lastSeenAt: grant?.lastSeenAt ?? null,
      mock,
    },
    caps: {
      mock,
      canQueryNode: canQuery,
      canAdminister,
      canAdmin: canAdminister,
      scopes: {
        joins: scopes.includes('joins'),
        topology: scopes.includes('topology'),
        value: scopes.includes('value'),
      },
    },
  };
}

/**
 * Push the current selection into the reactive store (and capabilities).
 */
function _syncAdministeredNode() {
  const { view, caps } = _deriveAdminView();

  // A selection change retargets every query: drop the previous target's rows
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
    scopes: caps.scopes,
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
 * The current administered-node view (seed-free).
 * @returns {object}
 */
export function getAdministeredNode() {
  return _deriveAdminView().view;
}

/**
 * Every node this browser can administer (stored grants, seed-free), each with
 * `active`/`selected` flags. The UI prepends its own `self` entry.
 * @returns {Array<object>}
 */
export function listAdministeredNodes() {
  return adminKeys.listAdminNodes();
}

/**
 * Select the administered node. `'self'` selects this browser's own node;
 * anything else must be a stored grant. Re-installs the singleton wasm admin
 * key when the target changed, clears page data so no stale rows are shown
 * under the new target, and re-derives capabilities.
 *
 * @param {string} nodeId `'self'`, `'mock'` (mock mode) or a granted node id.
 * @returns {string} the normalized selection.
 */
export function setAdministeredNode(nodeId) {
  const selected = adminKeys.selectAdminNode(nodeId);
  if (!_useMock && selected !== SELF && selected !== MOCK_NODE_ID) {
    try {
      _ensureAdminKey(selected);
    } catch (err) {
      _warnOnce('admin-select-key', '[api] could not install the admin key for the new target', err);
    }
  }
  _syncAdministeredNode();
  return selected;
}

/**
 * Ensure the wasm singleton admin key matches the stored key for `nodeId`.
 *
 * The wasm client holds exactly one admin key, so switching targets re-installs
 * the seed from the store rather than adding multi-key state to Rust.
 *
 * @param {string} nodeId
 * @param {object} [grant] Stored entry (seed-free); looked up when omitted.
 * @returns {object} the live client node.
 */
export function _ensureAdminKey(nodeId, grant = null) {
  const node = _requireNode();
  const target = String(nodeId).toLowerCase();
  const entry = grant ?? adminKeys.findAdminNode(target);
  if (!entry) throw new AdminUnavailableError('admin query');

  if (adminKeys.adminSeedState(target) === 'locked') {
    throw new AdminLockedError(target);
  }

  let installed = null;
  try {
    installed = node.admin_public_key?.() ?? null;
  } catch {
    installed = null;
  }
  if (installed && installed.toLowerCase() === entry.adminPubHex) return node;

  const seed = adminKeys.adminSeedBytes(target);
  if (!seed || seed.length !== 32) throw new AdminUnavailableError('admin query');
  try {
    node.set_admin_key(seed);
  } catch (err) {
    console.warn('[api] set_admin_key failed while switching admin target', err);
    throw new AdminUnavailableError('admin query');
  }
  return node;
}

/**
 * Unlock a protected (passphrase-wrapped) admin key, then install it.
 *
 * @param {string} nodeId
 * @param {string} passphrase
 * @returns {Promise<object>} the live client node
 * @throws on a wrong passphrase
 */
export async function ensureAdminUnlocked(nodeId, passphrase) {
  const target = String(nodeId).toLowerCase();
  await adminKeys.unlockAdminSeed(target, passphrase);
  return _ensureAdminKey(target);
}

/**
 * Lock a protected key for `nodeId`: clear the in-memory unlock cache and, when
 * it is the installed key, clear it from the wasm client so no further admin
 * call can use it.
 *
 * @param {string} nodeId
 */
export function lockAdmin(nodeId) {
  const target = String(nodeId).toLowerCase();
  const entry = adminKeys.findAdminNode(target);
  adminKeys.lockAdminSeed(target);
  if (entry && _clientNode) {
    try {
      const installed = _clientNode.admin_public_key?.() ?? null;
      if (installed && installed.toLowerCase() === entry.adminPubHex) {
        _clientNode.clear_admin_key?.();
      }
    } catch (err) {
      _warnOnce('admin-lock-clear', '[api] clear_admin_key failed', err);
    }
  }
  _syncAdministeredNode();
}

/**
 * Refuse a value action while its protected seed is locked, **before** any
 * request_id is generated or pending record written. Plain or session-unlocked
 * seeds pass.
 *
 * @param {string} target
 */
export function ensureValueSeedUnlocked(target) {
  const state = adminKeys.adminSeedState(target);
  if (state === 'locked') throw new AdminLockedError(target);
  if (state === 'absent') throw new AdminUnavailableError('admin value operation');
  // A value-scoped key must be wrapped before any value action ("required",
  // not opt-in). A plain non-value entry never reaches here (value actions are
  // gated on `scopes.value`).
  const entry = adminKeys.findAdminNode(target);
  if (state === 'plain' && entry?.scopes?.includes('value')) {
    throw new AdminSeedProtectionRequiredError(target);
  }
}

/**
 * Wrap a value-scoped admin seed under `passphrase` (required before any value
 * action). Refuses a non-value entry and any write that did not actually land.
 *
 * @param {string} nodeId
 * @param {string} passphrase
 * @returns {Promise<void>}
 */
export async function protectValueSeed(nodeId, passphrase) {
  const target = String(nodeId).toLowerCase();
  const entry = adminKeys.findAdminNode(target);
  if (!entry) throw new AdminUnavailableError('protect value key');
  if (!entry.scopes?.includes('value')) {
    throw new AdminUnavailableError('protect value key (value scope required)');
  }
  await adminKeys.protectAdminSeed(target, passphrase);
  // Fail closed for the caller: only report success when the row is wrapped.
  if (!adminKeys.findAdminNode(target)?.seedProtected) {
    throw new Error('Could not persist the protected value key (storage unavailable).');
  }
}

/**
 * Probe the selected node: one `AdminQuery` (or a local snapshot read for this
 * browser's own node) that establishes reachability, kind and address.
 * Records what it saw so the context bar can show it; never throws.
 *
 * @param {string} [nodeId] Target; defaults to the current selection.
 * @returns {Promise<{ nodeId: string, ok: boolean, kind: string, address: string|null, childrenCount: number|null, pendingCount: number|null, error: string|null }>}
 */
export async function probeAdminNode(nodeId = undefined) {
  const target = _normalizeTarget(nodeId);

  if (_useMock) {
    const children = MOCK_DATA.children;
    const view = {
      nodeId: target,
      ok: true,
      kind: inferNodeKind(children),
      address: target === SELF ? clientState.address ?? null : '0.3',
      childrenCount: children.length,
      pendingCount: MOCK_DATA.joinRequests.length,
      error: null,
    };
    if (target !== SELF && target !== MOCK_NODE_ID) {
      adminKeys.updateLastSeen(target, { status: 'active', kind: view.kind, address: view.address, at: Date.now() });
      _syncAdministeredNode();
    }
    return view;
  }

  if (target === SELF) {
    // Our own topology is local state: no grant and no network round-trip.
    try {
      const rows = _readLocalChildren();
      _selfKind = inferNodeKind(rows);
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

  const grant = adminKeys.findAdminNode(target);
  if (!grant) {
    return { nodeId: target, ok: false, kind: NODE_KIND.UNKNOWN, address: null, childrenCount: null, pendingCount: null, error: 'no-grant' };
  }
  if (grant.expiresAt <= Date.now()) {
    return { nodeId: target, ok: false, kind: grant.lastSeenKind ?? NODE_KIND.UNKNOWN, address: grant.lastSeenAddress, childrenCount: null, pendingCount: null, error: 'expired' };
  }

  try {
    const data = await _queryAdminSnapshot(target, grant); // reads + frees in one place
    const kind = inferNodeKind(data.children);
    const address = data.address ?? grant.nodeAddr ?? null;
    const at = Date.now();
    adminKeys.updateLastSeen(target, { status: 'active', kind, address, at });
    _syncAdministeredNode();
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
    adminKeys.updateLastSeen(target, { status: 'unreachable', at: Date.now() });
    _syncAdministeredNode();
    return {
      nodeId: target,
      ok: false,
      kind: grant.lastSeenKind ?? NODE_KIND.UNKNOWN,
      address: grant.lastSeenAddress,
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
 * Read this client's own children from the local topology snapshot (no grant,
 * no network round-trip).
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
 * Run one `AdminQuery` against `target` with the stored grant installed, then
 * copy the reply to plain data (freeing every handle it created).
 *
 * @param {string} target
 * @param {object} [grant]
 * @returns {Promise<{ nodeId: string|null, address: string|null, children: Array<object>, pending: number, pendingRows: Array<object> }>}
 */
async function _queryAdminSnapshot(target, grant = null) {
  const entry = grant ?? adminKeys.findAdminNode(target);
  if (!entry) throw new AdminUnavailableError('admin query');
  if (entry.expiresAt <= Date.now()) throw new AdminUnavailableError('admin query (grant expired)');
  const node = _ensureAdminKey(target, entry);
  const snapshot = await node.admin_query(target, entry.nodeAddr ?? null);
  return _readAdminSnapshot(snapshot);
}

/**
 * Copy an `AdminSnapshotDto` to plain data and free every wasm handle it
 * created (children, pending rows, the topology sub-snapshot, the snapshot).
 * Handles are read once and freed once: wasm-bindgen getters hand back a fresh
 * wrapper per access, so a second read would double-free.
 *
 * @param {object} snapshot
 * @returns {{ nodeId: string|null, address: string|null, children: Array<object>, pending: number, pendingRows: Array<object> }}
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
  if (accepted) _requestBalanceIfJoined();
}

/**
 * The most recently drained control event, as a plain object (or null).
 */
export function getLastControlEvent() {
  return _lastControlEvent ? { ..._lastControlEvent } : null;
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
  ledgerState.balance = status.balance;
  ledgerState.height = status.height;
  ledgerState.pinnedLedger = status.pinnedLedger;
  ledgerState.pending = status.pending;
  if (status.balance != null && ledgerState.verifiedAt == null) {
    // A balance restored from persisted state is still verified; stamp it.
    ledgerState.verifiedAt = Date.now();
  }
}

/**
 * Copy a wasm `LedgerStatusDto` to a plain object and free it.
 * @param {object} node
 * @returns {{ address: string|null, parent: string|null, balance: number|null, height: number|null, pinnedLedger: string|null, pending: number, activity: number }}
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
      pending: dto.pending,
      activity: dto.activity,
    };
  } finally {
    dto.free?.();
  }
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
    try {
      _clientNode.free?.();
    } catch {
      /* ignore */
    }
    _clientNode = null;
  }
  _releaseIdentityLock();
  _memorySeed = null;
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
  // Admin keys are device-local and identity-bound: wipe them too.
  adminKeys.clearAllAdminEntries();
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
 * @returns {{ address: string|null, parent: string|null, balance: number|null, height: number|null, pinnedLedger: string|null, pending: number, activity: number }}
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
 * Typed error raised when an action needs a protected (passphrase-wrapped) seed
 * that is currently locked. UI callers prompt for the passphrase and retry.
 */
export class AdminLockedError extends Error {
  constructor(nodeId = null) {
    super(
      nodeId
        ? `The value key for node ${nodeId} is locked. Unlock it with your passphrase to continue.`
        : 'The value key is locked. Unlock it with your passphrase to continue.',
    );
    this.name = 'AdminLockedError';
    this.code = 'ADMIN_LOCKED';
    this.nodeId = nodeId;
  }
}

/**
 * Typed error raised when a value action needs a still-plaintext value key.
 * Value actions require the key to be passphrase-wrapped first; UI callers open
 * the protect dialog and retry.
 */
export class AdminSeedProtectionRequiredError extends Error {
  constructor(nodeId = null) {
    super(
      nodeId
        ? `The value key for node ${nodeId} must be protected with a passphrase before any value action.`
        : 'The value key must be protected with a passphrase before any value action.',
    );
    this.name = 'AdminSeedProtectionRequiredError';
    this.code = 'ADMIN_SEED_PROTECT_REQUIRED';
    this.nodeId = nodeId;
  }
}

// ── Delegated admin keys ──────────────────────────────────────

/**
 * Generate a fresh delegated admin key for `nodeId` and install it on the live
 * client. The returned public key is what the operator grants with
 * `control admin grant`.
 *
 * The seed is persisted device-locally (adminKeys) and is never put into an
 * exported identity bundle. In mock mode no wasm is touched and a fake public
 * key is returned (nothing is persisted).
 *
 * @param {string} nodeId Target parent node id (64 hex).
 * @param {{ expirySeconds?: number|null, label?: string|null, nodeAddr?: string|null }} [opts]
 * @returns {Promise<{ nodeId: string, adminPubHex: string, nodeAddr: string|null }>}
 */
export async function configureAdminNode(
  nodeId,
  { expirySeconds = null, label = null, nodeAddr = null } = {},
) {
  if (typeof nodeId !== 'string' || !/^[0-9a-fA-F]{64}$/.test(nodeId)) {
    throw new Error('nodeId must be exactly 64 hex characters');
  }
  if (!adminKeys.isValidNodeAddr(nodeAddr)) {
    throw new Error(adminKeys.nodeAddrMessage);
  }

  const now = Date.now();
  const ttlSeconds = expirySeconds == null ? 7 * 24 * 3600 : Number(expirySeconds);
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error('expirySeconds must be a positive number');
  }
  const expiresAt = now + ttlSeconds * 1000;

  if (_useMock) {
    await mockDelay(200);
    const adminPubHex = _randomHex32();
    return { nodeId: nodeId.toLowerCase(), adminPubHex, nodeAddr: nodeAddr ?? null };
  }

  const node = _requireNode();
  const seed = _wasmModule.generate_secret_key();
  const seedBytes = seed instanceof Uint8Array ? seed : new Uint8Array(seed);
  if (seedBytes.length !== 32) {
    throw new Error('Failed to configure admin key: generated seed is not 32 bytes.');
  }
  node.set_admin_key(seedBytes);
  const adminPubHex = node.admin_public_key();
  if (typeof adminPubHex !== 'string' || !adminPubHex) {
    throw new Error('Failed to configure admin key: node returned no admin public key.');
  }

  adminKeys.addAdminEntry({
    nodeId,
    adminSeedHex: _bytesToHex(seedBytes),
    adminPubHex,
    grantedAt: now,
    expiresAt,
    label,
    nodeAddr,
  });
  // A first stored key becomes the selection; re-publish view + capabilities.
  _syncAdministeredNode();

  return { nodeId: nodeId.toLowerCase(), adminPubHex, nodeAddr: nodeAddr ?? null };
}

/**
 * Forget a delegated admin key: clears the live node's key when this is the
 * active entry, then removes the persisted entry.
 * @param {string} nodeId
 */
export function removeAdminNode(nodeId) {
  const target = String(nodeId).toLowerCase();
  const entry = adminKeys.findAdminNode(target);
  // Only clear the singleton wasm key when it is the key being removed.
  if (entry && _clientNode) {
    try {
      const installed = _clientNode.admin_public_key?.() ?? null;
      if (installed && installed.toLowerCase() === entry.adminPubHex) {
        _clientNode.clear_admin_key?.();
      }
    } catch (err) {
      _warnOnce('admin-clear-key', '[api] clear_admin_key failed', err);
    }
  }
  adminKeys.removeAdminNode(target);
  _syncAdministeredNode();
}

/**
 * Admin nodes for UI display (seed-free).
 * @returns {Array<{ nodeId: string, adminPubHex: string, scope: 'admin', scopes: string[], grantSource: 'manual'|'bundle', grantedAt: number, expiresAt: number, label: string|null, nodeAddr: string|null, active: boolean }>}
 */
export function getAdminNodes() {
  return adminKeys.listAdminNodes();
}

/**
 * Import a node-operator-signed `cawala://admin?node=&grant=` bundle.
 *
 * Parses and verifies the bundle in wasm, then applies its truthful
 * scopes/TTL to the **existing** stored key for the bundle's node. The browser
 * never holds operator/ledger keys: the bundle is public signed data, and the
 * admin seed already in this browser is preserved (only the grant's meaning
 * changes). Returns the updated seed-free entry.
 *
 * @param {string} uri
 * @returns {Promise<object>}
 * @throws {AdminUnavailableError} in mock mode (no live node).
 * @throws {Error} on an invalid/unverifiable bundle, no stored key, or a key mismatch.
 */
export async function applyAdminBundle(uri) {
  const trimmed = (uri || '').trim();
  if (!trimmed) {
    throw new Error('Paste an admin bundle link from a node operator.');
  }
  if (_useMock) {
    throw new AdminUnavailableError('apply admin bundle');
  }
  if (!_wasmModule) {
    throw new Error('Admin bundle import is unavailable: the wasm client is not loaded.');
  }

  let info;
  try {
    info = _wasmModule.parse_admin_bundle(trimmed);
  } catch (err) {
    throw new Error(`Invalid admin bundle: ${err?.message ?? err}`);
  }

  try {
    // Normalize the wasm getters (snake_case) into the plain camelCase shape
    // `applyAdminGrantInfo` takes, before the wasm object is freed.
    return applyAdminGrantInfo({
      node: info.node,
      admin: info.admin,
      scopes: Array.from(info.scopes || []),
      grantedAt: info.granted_at,
      expiry: info.expiry,
      label: info.label ?? null,
    });
  } finally {
    info.free?.();
  }
}

/**
 * The post-verification half of [`applyAdminBundle`]: apply already-parsed and
 * signature-verified bundle fields to the stored key for that node.
 *
 * Split out (and exported) so it is unit-testable without a wasm module. It
 * requires an existing entry, requires the bundle's admin key to match the
 * stored public key, and then delegates the strict scope/TTL update to
 * `adminKeys.applyAdminGrant`. Re-derives the administered-node view.
 *
 * @param {{ node: string, admin: string, scopes: string[], grantedAt: number, expiry: number, label?: string|null }} info
 * @returns {object} the updated seed-free stored entry
 */
export function applyAdminGrantInfo(info) {
  const nodeId = String(info?.node || '').toLowerCase();
  const entry = adminKeys.findAdminNode(nodeId);
  if (!entry) {
    throw new Error('generate a key for this node first');
  }
  if (String(info?.admin || '').toLowerCase() !== entry.adminPubHex) {
    throw new Error('This bundle grants a different admin key than the one stored for this node.');
  }
  const applied = adminKeys.applyAdminGrant(nodeId, {
    scopes: Array.from(info.scopes || []),
    grantedAt: info.grantedAt,
    expiresAt: info.expiry,
    label: info.label ?? null,
  });
  _syncAdministeredNode();
  return applied;
}

/**
 * Request to join a parent node.
 *
 * Accepts either a parsed invite object (from `parseInvite`, carrying `raw`),
 * a raw invite URI string, or a bare parent endpoint id.
 * @param {string|{ parent?: string, raw?: string, slot?: number, expiry?: number, operator?: string }} parsed
 * @param {string|null} [addressHint] Backward-compat unused hint.
 * @returns {Promise<{ status: string, reason?: string }>}
 */
export async function requestJoin(parsed, addressHint) {
  if (_useMock) {
    await mockDelay(600);
    return { status: JOIN_OUTCOME.PENDING };
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
  outcome.free?.();
  _persistState();
  _drainControlEvents();
  return reason ? { status, reason } : { status };
}

/**
 * Approve a pending join request.
 *
 * Live mode requires an active delegated admin key; without one this throws
 * `AdminUnavailableError` (as before). The wasm call may reject with a
 * `JsError` whose message is `admin request rejected: <stable_code>`.
 *
 * @param {string} childEndpointId
 * @param {number|null} [slot]
 * @returns {Promise<{ status: string, address: string|null, delivery: string }>}
 */
export async function approveJoin(childEndpointId, slot = null) {
  if (_useMock) {
    await mockDelay(400);
    const s = slot ?? 4;
    return { status: 'approved', address: `0.3.${s}`, delivery: 'delivered' };
  }
  const active = adminKeys.activeAdminNode();
  if (!active) throw new AdminUnavailableError('approve');

  const node = _ensureAdminKey(active.nodeId, active);
  const dto = await node.admin_approve_join(
    active.nodeId,
    childEndpointId,
    slot,
    active.nodeAddr ?? null,
  );
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
 * Reject a pending join request.
 *
 * Live mode requires an active delegated admin key; without one this throws
 * `AdminUnavailableError` (as before).
 *
 * @param {string} childEndpointId
 * @param {string|null} [reason]
 * @returns {Promise<{ status: string, delivery: string }>}
 */
export async function rejectJoin(childEndpointId, reason = null) {
  if (_useMock) {
    await mockDelay(300);
    return { status: 'rejected', delivery: 'delivered' };
  }
  const active = adminKeys.activeAdminNode();
  if (!active) throw new AdminUnavailableError('reject');

  const node = _ensureAdminKey(active.nodeId, active);
  const dto = await node.admin_reject_join(
    active.nodeId,
    childEndpointId,
    reason,
    active.nodeAddr ?? null,
  );
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
  if (_useMock) {
    await mockDelay(300);
    return { status: 'redelivered', delivery: 'delivered' };
  }
  const active = adminKeys.activeAdminNode();
  if (!active) throw new AdminUnavailableError('redeliver');

  const node = _ensureAdminKey(active.nodeId, active);
  const dto = await node.admin_redeliver_join(active.nodeId, childEndpointId, active.nodeAddr ?? null);
  try {
    return { status: 'redelivered', delivery: dto.delivery };
  } finally {
    dto.free?.();
  }
}

/**
 * Create a new child node.
 * @param {number|null} slot
 * @returns {Promise<{ status: string, address: string }>}
 */
export async function createChild(slot) {
  if (_useMock) {
    await mockDelay(500);
    const s = slot ?? 5;
    return { status: 'created', address: `0.3.${s}` };
  }
  throw new Error('Not implemented: real createChild');
}

/** Stable reject code → honest user-facing topology error copy. */
const TOPOLOGY_REJECT_MESSAGES = {
  unauthorized:
    'Topology grant expired or revoked. Ask the node operator to grant topology scope.',
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

/** Resolve the selected grant for a topology action, or throw. */
function _requireTopologyTarget(target) {
  const entry = adminKeys.findAdminNode(target);
  if (!entry || entry.expiresAt <= Date.now()) {
    throw new AdminUnavailableError('topology action (grant expired or missing)');
  }
  return entry;
}

/**
 * Detach a child from the administered node (topology scope).
 *
 * The browser never holds operator/ledger keys: the node applies the change via
 * the shared senior mutation engine. Refusals map to honest errors.
 *
 * @param {string} childEndpointId
 * @param {string} [nodeId] Target; defaults to the current selection.
 * @returns {Promise<{ status: 'detached', child: string }>}
 */
export async function adminDetachChild(childEndpointId, nodeId = undefined) {
  const target = _normalizeTarget(nodeId);
  if (_useMock) {
    await mockDelay(400);
    return { status: 'detached', child: childEndpointId };
  }
  if (!canAdministerTopology(administeredNode, adminCapabilities)) {
    throw new AdminUnavailableError('admin detach child (topology)');
  }
  const entry = _requireTopologyTarget(target);
  const node = _ensureAdminKey(target, entry);
  try {
    await node.admin_detach_child(target, childEndpointId, entry.nodeAddr ?? null);
  } catch (err) {
    throw _topologyError(err);
  }
  return { status: 'detached', child: childEndpointId };
}

/**
 * Re-slot a `node` child of the administered node (topology scope). `slot` of
 * `null` lets the node pick the lowest free slot.
 *
 * @param {string} childEndpointId
 * @param {number|null} slot
 * @param {string} [nodeId] Target; defaults to the current selection.
 * @returns {Promise<{ status: 'moved', child: string, slot: number|null }>}
 */
export async function adminMoveChild(childEndpointId, slot = null, nodeId = undefined) {
  const target = _normalizeTarget(nodeId);
  if (_useMock) {
    await mockDelay(500);
    return { status: 'moved', child: childEndpointId, slot: slot ?? null };
  }
  if (!canAdministerTopology(administeredNode, adminCapabilities)) {
    throw new AdminUnavailableError('admin move child (topology)');
  }
  const entry = _requireTopologyTarget(target);
  const node = _ensureAdminKey(target, entry);
  try {
    await node.admin_move_child(target, childEndpointId, slot ?? null, entry.nodeAddr ?? null);
  } catch (err) {
    throw _topologyError(err);
  }
  return { status: 'moved', child: childEndpointId, slot: slot ?? null };
}

// ── Delegated value administration (P5) ───────────────────────

/** localStorage key for the single in-flight value operation. */
export const VALUE_PENDING_KEY = 'cawala.value.pending.v1';

/**
 * Whether the current administered-node capabilities permit a value operation:
 * a value scope on a **non-self** target. Pure, so it is unit-testable.
 * @param {{ isSelf?: boolean }|null|undefined} view
 * @param {{ scopes?: { value?: boolean } }|null|undefined} caps
 * @returns {boolean}
 */
export function canAdministerValue(view, caps) {
  return Boolean(view != null && !view.isSelf && caps?.scopes?.value);
}

/** Reject-code → honest user-facing value error copy. */
const VALUE_REJECT_MESSAGES = {
  limit_exceeded:
    'This exceeds the operator\u2019s per-request, window, or account limit. Ask the node operator for the current limits, or use a smaller amount.',
  insufficient_balance: 'That burn exceeds the account\u2019s current balance.',
  unauthorized:
    'Value grant expired or revoked. Ask the node operator to grant value scope.',
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
 * Run one delegated value operation (issue or burn), persisting the
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
  const target = _normalizeTarget(nodeId);

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
    throw new AdminUnavailableError('admin value operation (value)');
  }
  // Fail closed on a locked protected seed BEFORE generating a request_id or
  // writing the pending record (a retry must not burn a fresh id).
  ensureValueSeedUnlocked(target);

  const entry = adminKeys.findAdminNode(target);
  if (!entry || entry.expiresAt <= Date.now()) {
    throw new AdminUnavailableError('admin value operation (grant expired or missing)');
  }
  const node = _ensureAdminKey(target, entry);
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
        ? await node.admin_issue(target, requestId, account, amount, reason, entry.nodeAddr ?? null)
        : await node.admin_burn(target, requestId, account, amount, reason, entry.nodeAddr ?? null);
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
 * Get the children of the administered node.
 *
 * - mock: the synthetic child list (mock is a data source, not a layout).
 * - `self`: this browser's own local topology snapshot (no grant needed).
 * - a granted node: its `AdminQuery` topology snapshot.
 *
 * Each row carries `kind` (`node` | `user`) so the UI can infer the target's
 * node kind; `balance` is always null here — no ledger query exists in P1 and
 * balances are never fabricated.
 *
 * @param {string} [nodeId] Target; defaults to the current selection.
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
 * Record what an admin query saw about a target (status/kind/address) and
 * refresh the stored view. Failures mark the node unreachable rather than
 * dropping the last known kind.
 * @param {string} target
 * @param {{ ok: boolean, kind?: string, address?: string|null, error?: any }} outcome
 */
function _recordQueryOutcome(target, outcome) {
  if (target === SELF || target === MOCK_NODE_ID) {
    if (outcome.kind) {
      _selfKind = outcome.kind;
      _syncAdministeredNode();
    }
    return;
  }
  const now = Date.now();
  if (outcome.ok) {
    adminKeys.updateLastSeen(target, {
      status: 'active',
      kind: outcome.kind ?? null,
      address: outcome.address ?? null,
      at: now,
    });
  } else {
    adminKeys.updateLastSeen(target, { status: 'unreachable', at: now });
  }
  _syncAdministeredNode();
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
 * Whether the current administered-node capabilities permit a value-scoped
 * ledger read. Pure, so it is unit-testable.
 * @param {{ scopes?: { value?: boolean } }|null|undefined} caps
 * @returns {boolean}
 */
export function canReadAdminLedger(caps) {
  return Boolean(caps?.scopes?.value);
}

/**
 * Whether the delegated-admin surface permits topology actions: a topology
 * scope on a **non-self** target. Pure, so it is unit-testable.
 * @param {{ isSelf?: boolean }|null|undefined} view
 * @param {{ scopes?: { topology?: boolean } }|null|undefined} caps
 * @returns {boolean}
 */
export function canAdministerTopology(view, caps) {
  return Boolean(view != null && !view.isSelf && caps?.scopes?.topology);
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
 * Get accounts for the administered node.
 *
 * - mock: the synthetic accounting rows (with derived equity).
 * - `self`: this browser's verified balance, only once a receipt exists (the
 *   cryptographically verified leaf path).
 * - a value-scoped administered node: the node's own read-only accounting
 *   snapshot (`AdminLedgerQuery`), mapped to the same row shape. A joins-only
 *   or topology-only grant cannot read balances and yields `[]`. Balances are
 *   node-asserted and never fabricated here.
 *
 * @param {string} [nodeId] Target; defaults to the current selection.
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

  // An administered node: only a value-scoped grant may read its books.
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
      address: adminKeys.findAdminNode(target)?.nodeAddr ?? null,
    });
    return rows;
  } catch (err) {
    _recordQueryOutcome(target, { ok: false, error: err });
    _warnOnce(`admin-ledger:${target}`, '[api] admin_ledger_query failed', err);
    return [];
  }
}

/**
 * Run one value-scoped ledger query (direct first, routed fallback inside the
 * wasm `admin_ledger_query`) and read the reply into a plain snapshot object.
 * @param {string} target
 * @param {object} [grant]
 * @returns {Promise<object>}
 */
async function _queryAdminLedger(target, grant = null) {
  const entry = grant ?? adminKeys.findAdminNode(target);
  if (!entry) throw new AdminUnavailableError('admin ledger query');
  if (entry.expiresAt <= Date.now()) {
    throw new AdminUnavailableError('admin ledger query (grant expired)');
  }
  const node = _ensureAdminKey(target, entry);
  const snapshot = await node.admin_ledger_query(target, entry.nodeAddr ?? null);
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
 * Get pending join requests for the administered node.
 *
 * Live mode needs a valid grant over the target (mock always has data).
 * A missing/expired grant yields `[]` — the page decides which empty state to
 * show from `adminCapabilities`. An unreachable target records `unreachable`
 * so the context bar can say so.
 *
 * @param {string} [nodeId] Target; defaults to the current selection.
 * @returns {Promise<Array>}
 */
export async function getJoinRequests(nodeId = undefined) {
  const target = _normalizeTarget(nodeId);
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.joinRequests];
  }

  const grant = adminKeys.findAdminNode(target);
  if (!grant || grant.expiresAt <= Date.now()) return [];

  try {
    const data = await _queryAdminSnapshot(target, grant);
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
    orderHash: isSettlement ? entry.orderHash : (entry.orderHash ?? null),
  };
}

/**
 * Get activity log entries for the administered node.
 *
 * - mock: the synthetic log.
 * - `this browser's leaf`: the locally reported payment/settlement history.
 * - a granted node: `[]` — an administered-node activity log does not exist
 *   in this phase, and this browser's own payments must not be shown under
 *   another node's name.
 *
 * @param {object} [filters]
 * @param {string} [filters.type]
 * @param {string} [filters.address]
 * @param {string} [nodeId] Target; defaults to the current selection.
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
 * @returns {{ state: string, parent: string|null, slot: number|null, address: string|null, reason: string|null }}
 */
export function getJoinStatus() {
  if (_useMock) {
    return {
      state: JOIN_STATE.JOINED,
      parent: null,
      slot: null,
      address: '0.3.1',
      reason: null,
    };
  }
  if (!_clientNode) {
    return { state: JOIN_STATE.NONE, parent: null, slot: null, address: null, reason: null };
  }
  return _readJoinStatus(_clientNode);
}

/**
 * Copy a wasm `JoinStatus` DTO to a plain object and free it.
 * @param {object} node
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
 * @param {string} b64
 * @returns {Uint8Array}
 */
function _base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
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
