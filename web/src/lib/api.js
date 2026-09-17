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
  ENVELOPE_ACK,
  JOIN_STATE,
  JOIN_OUTCOME,
  CONTROL_EVENT,
  LEDGER_EVENT,
  ORDER_STATUS,
} from './constants.js';
import { clientState, ledgerState } from './stores.svelte.js';
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
    return {
      endpointId: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      address: '0.3.1',
    };
  }
  const node = _requireNode();
  const status = _readJoinStatus(node);
  const address = status.address ?? null;
  if (address) _requestBalanceIfJoined();
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
 * Get connection status.
 * @returns {string} One of CONNECTION.*
 */
export function getConnectionStatus() {
  if (_useMock) return CONNECTION.CONNECTED;
  return _clientNode ? CONNECTION.CONNECTED : CONNECTION.DISCONNECTED;
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

  return { nodeId: nodeId.toLowerCase(), adminPubHex, nodeAddr: nodeAddr ?? null };
}

/**
 * Forget a delegated admin key: clears the live node's key when this is the
 * active entry, then removes the persisted entry.
 * @param {string} nodeId
 */
export function removeAdminNode(nodeId) {
  const active = adminKeys.activeAdminNode();
  if (active && active.nodeId === String(nodeId).toLowerCase()) {
    try {
      _clientNode?.clear_admin_key?.();
    } catch (err) {
      _warnOnce('admin-clear-key', '[api] clear_admin_key failed', err);
    }
  }
  adminKeys.removeAdminNode(nodeId);
}

/**
 * Admin nodes for UI display (seed-free).
 * @returns {Array<{ nodeId: string, adminPubHex: string, scope: 'admin', grantedAt: number, expiresAt: number, label: string|null, nodeAddr: string|null, active: boolean }>}
 */
export function getAdminNodes() {
  return adminKeys.listAdminNodes();
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

  const node = _requireNode();
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

  const node = _requireNode();
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

  const node = _requireNode();
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

/**
 * Move a child to a new slot/parent.
 * @param {string} childAddress
 * @param {string} newParentAddress
 * @param {number} newSlot
 * @returns {Promise<{ status: string, newAddress: string }>}
 */
export async function moveChild(childAddress, newParentAddress, newSlot) {
  if (_useMock) {
    await mockDelay(500);
    return { status: 'moved', newAddress: `${newParentAddress}.${newSlot}` };
  }
  throw new Error('Not implemented: real moveChild');
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
 * Get the list of children for this node from the local topology snapshot.
 * Empty for a leaf.
 * @returns {Promise<Array>}
 */
export async function getChildren() {
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.children];
  }

  const node = _requireNode();
  const snap = node.local_snapshot();
  // Read the children list once: the getter may hand back fresh wasm handles
  // on each access, so caching is required to free the exact objects we mapped.
  const children = snap.children;
  try {
    return children.map((child) => ({
      address: child.address ?? null,
      endpointId: child.child_id,
      balance: null,
      seniority: new Date(child.date_joined * 1000).toISOString(),
      online: false,
      slot: child.slot,
    }));
  } finally {
    for (const child of children) child.free?.();
    snap.free?.();
  }
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
 * Get accounts held by this node. No ledger backend is exposed to the web
 * client in this increment, so live mode returns an empty list rather than
 * fabricating balances.
 * @returns {Promise<Array>}
 */
export async function getAccounts() {
  if (_useMock) {
    await mockDelay(200);
    return withDerivedEquity(MOCK_DATA.accounts);
  }
  // Only expose a real account once a cryptographically verified balance
  // exists; never fabricate a zero balance before the first receipt.
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

/**
 * Get pending join requests.
 *
 * Live mode requires an active delegated admin key: it queries the target
 * node's admin snapshot and maps each pending join. Without an active admin
 * key it returns an empty list (as before).
 * @returns {Promise<Array>}
 */
export async function getJoinRequests() {
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.joinRequests];
  }

  const active = adminKeys.activeAdminNode();
  if (!active) return [];

  let snapshot;
  try {
    snapshot = await _requireNode().admin_query(active.nodeId, active.nodeAddr ?? null);
  } catch (err) {
    _warnOnce('admin-query', '[api] admin_query failed', err);
    return [];
  }

  // Cache the pending list once: the getter may hand back fresh wasm handles
  // on each access, so we must free the exact objects we mapped.
  const rows = snapshot.pending ?? [];
  try {
    return rows.map((row) => ({
      endpointId: row.child_id,
      requestedAddress: null,
      slot: row.desired_slot ?? null,
      kind: row.kind ?? null,
      operator: row.operator ?? null,
      expiry: row.expiry ?? null,
      timestamp: null,
      status: 'pending',
      nodeId: active.nodeId,
    }));
  } finally {
    for (const row of rows) row.free?.();
    snapshot.free?.();
  }
}

/**
 * Get activity log entries. No backend is exposed to the web client in this
 * increment, so live mode returns an empty list.
 * @param {object} [filters]
 * @param {string} [filters.type]
 * @param {string} [filters.address]
 * @returns {Promise<Array>}
 */
export async function getActivityLog(filters) {
  if (_useMock) {
    await mockDelay(200);
    let entries = [...MOCK_DATA.activity];
    if (filters?.type) {
      entries = entries.filter((e) => e.type === filters.type);
    }
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
  // Live: UI-shaped entries accumulated by the ledger-event poller.
  let entries = [...ledgerState.activity];
  if (filters?.type) {
    entries = entries.filter((e) => e.type === filters.type);
  }
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
  return {
    mock: _useMock,
    canAdmin: !_useMock && !!adminKeys.activeAdminNode(),
    canQueryPeers: false,
    identityPersistent: _identityPersistent,
    multiTabLeader: _multiTabLeader,
    multiTabWarning: _multiTabWarning,
  };
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
    },
    {
      address: '0.3.2',
      endpointId: 'z6MkRt5nYh7kJf3gWp2xDs9cVq6bLm4eAf8uOiIiPpOo',
      balance: 800,
      seniority: '2025-03-22T00:00:00Z',
      online: false,
      slot: 2,
    },
    {
      address: '0.3.3',
      endpointId: 'z6MkBu4iNk8mHj2fXs7cWr5eVq3dLp9gAj6uOiIiPpOo',
      balance: 2100,
      seniority: '2024-11-08T00:00:00Z',
      online: true,
      slot: 3,
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
