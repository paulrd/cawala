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
} from './constants.js';

// ── Internal state ────────────────────────────────────────────

let _useMock = true;
let _wasmModule = null;
let _clientNode = null;

// Identity/state storage keys.
const IDENTITY_KEY = 'cawala.identity.v1';
const STATE_KEY = 'cawala.state.v1';
const SEED_BYTES = 32;

let _identityPersistent = false;
let _memorySeed = null; // in-session fallback when localStorage is unusable

// Control-event poller + last drained event.
let _controlPoller = null;
let _lastControlEvent = null;

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
 * Load the persisted postcard state blob, if any.
 * @returns {Uint8Array|null}
 */
function _loadState() {
  let b64 = null;
  try {
    b64 = window.localStorage.getItem(STATE_KEY);
  } catch (err) {
    _warnOnce('state-read', '[api] localStorage unavailable for state read', err);
    return null;
  }
  if (!b64) return null;
  try {
    return _base64ToBytes(b64);
  } catch (err) {
    _warnOnce('state-decode', '[api] persisted state is malformed; ignoring it', err);
    return null;
  }
}

/**
 * Persist `node.export_state()` to localStorage. Best-effort; never throws.
 */
function _persistState() {
  if (!_clientNode) return;
  try {
    const bytes = _clientNode.export_state();
    window.localStorage.setItem(STATE_KEY, _bytesToBase64(bytes));
  } catch (err) {
    _warnOnce('state-write', '[api] could not persist client state (private mode/quota)', err);
  }
}

/**
 * Spawn the real control client, restore state, and start the event poller.
 * @returns {Promise<import('../wasm/cawala_client.js').ClientNode>}
 */
async function _spawnRealNode() {
  const seed = _loadOrCreateIdentity(_wasmModule);
  const node = await _wasmModule.ClientNode.spawn_control(seed);

  const stateBytes = _loadState();
  if (stateBytes) {
    try {
      node.import_state(stateBytes);
    } catch (err) {
      console.warn('[api] import_state failed; starting from a fresh local state', err);
    }
  }

  _clientNode = node;
  _persistState();
  _startControlPoller();
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
 * Start the 2 s control-event drain loop (idempotent).
 */
function _startControlPoller() {
  if (_controlPoller != null) return;
  _controlPoller = setInterval(_drainControlEvents, 2000);
}

/**
 * Stop the control-event drain loop.
 */
function _stopControlPoller() {
  if (_controlPoller != null) {
    clearInterval(_controlPoller);
    _controlPoller = null;
  }
}

/**
 * Drain all queued control events into `_lastControlEvent`, copying each DTO to
 * a plain object and freeing it. Persists state when anything was drained.
 */
function _drainControlEvents() {
  if (_useMock || !_clientNode) return;
  let drained = false;
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
      ev.free?.();
      drained = true;
    }
  } catch (err) {
    _warnOnce('control-drain', '[api] control event drain failed', err);
    return;
  }
  if (drained) _persistState();
}

/**
 * The most recently drained control event, as a plain object (or null).
 */
export function getLastControlEvent() {
  return _lastControlEvent ? { ..._lastControlEvent } : null;
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
  return {
    endpointId: node.endpoint_id(),
    address: status.address ?? null,
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
      _clientNode.free?.();
    } catch {
      /* ignore */
    }
    _clientNode = null;
  }
  _releaseIdentityLock();
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
 * Approve a pending join request. Not available in the web client.
 * @param {string} childEndpointId
 * @param {number|null} slot
 * @returns {Promise<{ status: string, address: string }>}
 */
export async function approveJoin(childEndpointId, slot) {
  if (_useMock) {
    await mockDelay(400);
    const s = slot ?? 4;
    return { status: 'approved', address: `0.3.${s}` };
  }
  throw new AdminUnavailableError('approve');
}

/**
 * Reject a pending join request. Not available in the web client.
 * @param {string} childEndpointId
 * @returns {Promise<{ status: string }>}
 */
export async function rejectJoin(childEndpointId) {
  if (_useMock) {
    await mockDelay(300);
    return { status: 'rejected' };
  }
  throw new AdminUnavailableError('reject');
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
 * Detach a child.
 * @param {string} childAddress
 * @returns {Promise<{ status: string }>}
 */
export async function detachChild(childAddress) {
  if (_useMock) {
    await mockDelay(400);
    return { status: 'detached' };
  }
  throw new Error('Not implemented: real detachChild');
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
    if (url.protocol === 'cawala:' && url.pathname === '/join') {
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
 * Get accounts held by this node. No ledger backend is exposed to the web
 * client in this increment, so live mode returns an empty list rather than
 * fabricating balances.
 * @returns {Promise<Array>}
 */
export async function getAccounts() {
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.accounts];
  }
  return [];
}

/**
 * Get pending join requests. Pending joins are not exposed by the protocol, so
 * live mode returns an empty list.
 * @returns {Promise<Array>}
 */
export async function getJoinRequests() {
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.joinRequests];
  }
  return [];
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
  return [];
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
    canAdmin: false,
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
    // Equity
    {
      address: '0.3',
      type: 'equity',
      label: 'Node equity',
      balance: 400,
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
