/**
 * Cawala — delegated admin key + administered-node selection store (v2).
 *
 * A browser can be granted delegated admin authority (K_admin) over one or
 * more nodes. The generated admin seed is device-local key material: it is
 * persisted here (never in any exported identity bundle) and handed to the wasm
 * client via `api.configureAdminNode()` -> `ClientNode.set_admin_key()`.
 *
 * Storage: `cawala.admin.v2`, shape:
 *   { v: 2, selected: 'self' | <nodeId> | null, entries: [ {
 *       nodeId, adminSeedHex, adminPubHex, scope: 'admin',
 *       scopes: ['joins' | 'topology' | 'value'],
 *       grantSource: 'manual' | 'bundle',
 *       grantedAt, expiresAt, label, nodeAddr,
 *       lastSeenStatus, lastSeenKind, lastSeenAddress, lastSeenAt } ] }
 *
 * `grantSource` is `'manual'` for a locally generated provisional grant (and
 * for pre-P2 rows) and `'bundle'` once an operator-signed `cawala://admin`
 * bundle has been applied via `applyAdminGrant` (which replaces the
 * provisional scopes/TTL without touching the seed).
 *
 * Read-migration: a v1 envelope at `cawala.admin.v1` is read once, rewritten
 * as v2 (and the v1 key dropped) — see `_migrateV1()`. v1 grants are
 * interpreted as `scopes: ['joins']`; a v1 grant is never silently widened.
 *
 * Selection is explicit. `activeAdminNode()` is the *selected* entry while it
 * is still valid — it is never an implicit "first non-expired entry". The only
 * implicit moments are one-time defaults that are persisted immediately: the
 * v1 -> v2 migration and the very first stored entry.
 *
 * `nodeAddr` (dotted octal, e.g. "0.1.2") is the target node's asserted address
 * used for tree-routed admin calls. It is additive: entries stored before it
 * existed read back as `nodeAddr: null`.
 *
 * Every public accessor except `adminSeedBytes()` returns seed-free views, so
 * accidental logging/serialization can never leak K_admin. Pure ESM, no DOM
 * beyond localStorage, dependency-free and Node-testable.
 */

const STORE_KEY_V1 = 'cawala.admin.v1';
const STORE_KEY = 'cawala.admin.v2';
const STORE_VERSION = 2;
const DEFAULT_TTL_MS = 7 * 24 * 3600 * 1000;

/** Selection value meaning "this browser's own node", not a granted node. */
export const SELF_SELECTION = 'self';

/**
 * Selection values that never name a stored grant. `'mock'` is the synthetic
 * administered node shown only in mock mode; it is a UI pointer, never a key.
 */
export const SPECIAL_SELECTIONS = [SELF_SELECTION, 'mock'];

/**
 * Whether `value` is a special (non-grant) selection.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isSpecialSelection(value) {
  return SPECIAL_SELECTIONS.includes(value);
}

/** Scopes a v1 (`scope: 'admin'`) grant is honoured with — never widened. */
const V1_SCOPES = ['joins'];
const KNOWN_SCOPES = ['joins', 'topology', 'value'];

/**
 * Where a stored grant's authority came from.
 * - `manual`: a locally generated key with an invented/provisional TTL.
 * - `bundle`: scopes/TTL imported from a node-operator-signed `cawala://admin`
 *   bundle and therefore truthful.
 */
export const GRANT_SOURCE = {
  MANUAL: 'manual',
  BUNDLE: 'bundle',
};

const HEX64 = /^[0-9a-f]{64}$/i;
const HEX64_MESSAGE = {
  nodeId: 'nodeId must be exactly 64 hex characters',
  adminSeedHex: 'adminSeedHex must be exactly 64 hex characters',
  adminPubHex: 'adminPubHex must be exactly 64 hex characters',
};

// Dotted octal nodal address: one digit per level, each 0..=7. Accepts "0" and
// "0.1.2"; rejects empty, leading/trailing dots ("0.", ".0"), non-octal digits
// ("8", "00").
const NODE_ADDR = /^[0-7](?:\.[0-7])*$/;
export const nodeAddrMessage =
  'nodeAddr must be a dotted octal address such as "0" or "0.1.2" (each level 0-7)';

/**
 * Resolve a localStorage-like object, or null when storage is unavailable
 * (SSR, private mode, quota). Never throws.
 * @returns {Storage|null}
 */
function _storage() {
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

function _isHex64(value) {
  return typeof value === 'string' && HEX64.test(value);
}

function _requireHex64(value, message) {
  if (!_isHex64(value)) throw new Error(message);
  return value.toLowerCase();
}

/**
 * Validate and normalize an optional nodal address.
 * @param {unknown} value
 * @returns {string|null}
 */
export function isValidNodeAddr(value) {
  return value == null || (typeof value === 'string' && NODE_ADDR.test(value));
}

function _requireNodeAddr(value) {
  if (value == null) return null;
  if (!isValidNodeAddr(value)) throw new Error(nodeAddrMessage);
  return value;
}

/** Normalize a scopes list; anything unusable falls back to joins-only. */
function _normalizeScopes(value, fallback = V1_SCOPES) {
  if (!Array.isArray(value)) return [...fallback];
  const scopes = value.filter((s) => KNOWN_SCOPES.includes(s));
  return scopes.length > 0 ? scopes : [...fallback];
}

/**
 * Strictly validate the scopes of a verified bundle.
 *
 * Unlike `_normalizeScopes`, this never falls back: an unknown or empty scope
 * set is an error, so a verified grant is never silently widened or narrowed to
 * joins-only.
 * @param {unknown} value
 * @returns {string[]} deduped scopes in the order given
 */
function _requireScopes(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('A verified admin grant must list at least one scope');
  }
  const out = [];
  for (const scope of value) {
    if (!KNOWN_SCOPES.includes(scope)) {
      throw new Error(`Unknown admin scope: ${String(scope)}`);
    }
    if (!out.includes(scope)) out.push(scope);
  }
  return out;
}

function _hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.substr(i, 2), 16);
  return out;
}

/**
 * Seed-free view of a stored record (what every public accessor returns).
 * @param {object} record
 */
function _publicEntry(record) {
  return {
    nodeId: record.nodeId,
    adminPubHex: record.adminPubHex,
    scope: record.scope,
    scopes: [...record.scopes],
    grantSource: record.grantSource === GRANT_SOURCE.BUNDLE ? GRANT_SOURCE.BUNDLE : GRANT_SOURCE.MANUAL,
    grantedAt: record.grantedAt,
    expiresAt: record.expiresAt,
    label: record.label,
    nodeAddr: record.nodeAddr ?? null,
    lastSeenStatus: record.lastSeenStatus ?? null,
    lastSeenKind: record.lastSeenKind ?? null,
    lastSeenAddress: record.lastSeenAddress ?? null,
    lastSeenAt: record.lastSeenAt ?? null,
  };
}

/**
 * Validate + normalize one raw stored entry. Returns null for anything
 * malformed so a single bad row cannot poison the whole store.
 * @param {unknown} entry
 * @returns {object|null}
 */
function _normalizeStored(entry) {
  if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) return null;
  if (!_isHex64(entry.nodeId) || !_isHex64(entry.adminSeedHex) || !_isHex64(entry.adminPubHex)) {
    return null;
  }
  const grantedAt = Number(entry.grantedAt);
  const expiresAt = Number(entry.expiresAt);
  if (!Number.isFinite(grantedAt) || !Number.isFinite(expiresAt) || !(expiresAt > grantedAt)) {
    return null;
  }
  return {
    nodeId: entry.nodeId.toLowerCase(),
    adminSeedHex: entry.adminSeedHex.toLowerCase(),
    adminPubHex: entry.adminPubHex.toLowerCase(),
    scope: 'admin',
    // v1 rows carry `scope: 'admin'` and no `scopes`: joins-only, never widened.
    scopes: _normalizeScopes(entry.scopes, V1_SCOPES),
    // Additive field: pre-existing/provisional rows without a bundle read as
    // `manual`.
    grantSource: entry.grantSource === GRANT_SOURCE.BUNDLE ? GRANT_SOURCE.BUNDLE : GRANT_SOURCE.MANUAL,
    grantedAt,
    expiresAt,
    label: typeof entry.label === 'string' ? entry.label : null,
    // Additive field: pre-existing rows without a valid `nodeAddr` read as null.
    nodeAddr: isValidNodeAddr(entry.nodeAddr) ? (entry.nodeAddr ?? null) : null,
    lastSeenStatus: typeof entry.lastSeenStatus === 'string' ? entry.lastSeenStatus : null,
    lastSeenKind: typeof entry.lastSeenKind === 'string' ? entry.lastSeenKind : null,
    lastSeenAddress: typeof entry.lastSeenAddress === 'string' ? entry.lastSeenAddress : null,
    // `null` must stay `null`: `Number(null)` is 0, which would turn a never-
    // probed node into "seen in 1970".
    lastSeenAt:
      entry.lastSeenAt == null || !Number.isFinite(Number(entry.lastSeenAt))
        ? null
        : Number(entry.lastSeenAt),
  };
}

/** Normalize a raw selection value, or null when it names nothing known. */
function _normalizeSelection(value) {
  if (typeof value !== 'string') return null;
  const lower = value.toLowerCase();
  if (isSpecialSelection(lower)) return lower;
  return HEX64.test(lower) ? lower : null;
}

/** Whether `selected` still resolves (a special value or a stored entry). */
function _isKnownSelection(selected, entries) {
  if (selected == null) return false;
  if (isSpecialSelection(selected)) return true;
  return entries.some((entry) => entry.nodeId === selected);
}

/** Parse a raw envelope (any accepted version) into a normalized shape. */
function _parseEnvelope(raw) {
  if (typeof raw !== 'string' || !raw) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    (parsed.v !== 1 && parsed.v !== STORE_VERSION) ||
    !Array.isArray(parsed.entries)
  ) {
    return null;
  }
  const entries = [];
  for (const row of parsed.entries) {
    const record = _normalizeStored(row);
    if (record) entries.push(record);
  }
  return { v: parsed.v, selected: _normalizeSelection(parsed.selected), entries };
}

/**
 * One-time default selection used when a stored pointer is missing or points
 * at a removed entry. Persisted immediately, so runtime behaviour is explicit
 * from then on.
 * @param {Array<object>} entries
 * @param {number} now
 * @returns {string}
 */
function _defaultSelection(entries, now) {
  const active = entries.filter((e) => e.expiresAt > now);
  if (active.length === 0) return SELF_SELECTION;
  // Most recently granted active entry: stable and explainable, then persisted.
  return active.reduce((best, e) => (e.grantedAt > best.grantedAt ? e : best)).nodeId;
}

/**
 * Read the raw store, migrating a v1 envelope to v2 on first read.
 * Returns `{ selected, entries }` or null when nothing usable is stored.
 * @param {number} now
 */
function _readEnvelope(now = Date.now()) {
  const store = _storage();
  if (!store) return null;

  let rawV2 = null;
  try {
    rawV2 = store.getItem(STORE_KEY);
  } catch {
    return null;
  }

  let envelope = _parseEnvelope(rawV2);

  if (!envelope) {
    // No (or unusable) v2 store: try the legacy v1 location and migrate.
    let rawV1 = null;
    try {
      rawV1 = store.getItem(STORE_KEY_V1);
    } catch {
      return null;
    }
    const legacy = _parseEnvelope(rawV1);
    if (!legacy) return null;
    envelope = { v: STORE_VERSION, selected: legacy.selected, entries: legacy.entries };
    _writeEnvelope(envelope); // writes v2, then drops the v1 key
  }

  if (!_isKnownSelection(envelope.selected, envelope.entries)) {
    envelope.selected = _defaultSelection(envelope.entries, now);
    _writeEnvelope(envelope);
  }
  return envelope;
}

/**
 * Persist an envelope at the v2 key and retire the v1 key. Best-effort: an
 * unavailable/full store is a silent no-op (the v1 key is only dropped once
 * the v2 write has been attempted, so a failed write never destroys data).
 * @param {{ selected: string|null, entries: Array<object> }} envelope
 */
function _writeEnvelope(envelope) {
  const store = _storage();
  if (!store) return;
  try {
    store.setItem(
      STORE_KEY,
      JSON.stringify({
        v: STORE_VERSION,
        selected: envelope.selected ?? null,
        entries: envelope.entries,
      }),
    );
    store.removeItem(STORE_KEY_V1);
  } catch {
    /* ignore */
  }
}

// ── Read accessors ────────────────────────────────────────────

/**
 * All stored admin entries as seed-free objects. Malformed/unavailable
 * storage yields `[]`; never throws.
 * @param {number} [now] epoch millis
 * @returns {Array<object>}
 */
export function loadAdminEntries(now = Date.now()) {
  const envelope = _readEnvelope(now);
  return envelope ? envelope.entries.map(_publicEntry) : [];
}

/**
 * UI-facing list of admin nodes with an `active` flag. Never returns the seed.
 * @param {number} [now] epoch millis
 * @returns {Array<object>}
 */
export function listAdminNodes(now = Date.now()) {
  return loadAdminEntries(now).map((entry) => ({
    ...entry,
    active: entry.expiresAt > now,
    selected: entry.nodeId === selectedNodeId(),
  }));
}

/**
 * Find one admin entry by node id (seed-free). Case-insensitive.
 * @param {string} nodeId
 * @returns {object|null}
 */
export function findAdminNode(nodeId) {
  if (typeof nodeId !== 'string') return null;
  const wanted = nodeId.toLowerCase();
  const record = _readEnvelope()?.entries.find((entry) => entry.nodeId === wanted) ?? null;
  return record ? _publicEntry(record) : null;
}

// ── Selection ─────────────────────────────────────────────────

/**
 * The explicit selection: `'self'` (this browser's own node), a granted
 * node id, or `null` only when storage is unavailable and nothing was ever
 * selected in this session.
 * @returns {string|null}
 */
export function selectedNodeId() {
  const envelope = _readEnvelope();
  if (envelope) return envelope.selected;
  return null;
}

/**
 * Explicitly select an administered node.
 * @param {string} nodeId `'self'` or the id of a stored entry.
 * @returns {string} the normalized selection.
 */
export function selectAdminNode(nodeId) {
  const value = String(nodeId ?? '').toLowerCase();
  if (!isSpecialSelection(value) && !_isHex64(value)) {
    throw new Error(HEX64_MESSAGE.nodeId);
  }
  const envelope = _readEnvelope() ?? { selected: null, entries: [] };
  if (!isSpecialSelection(value) && !envelope.entries.some((e) => e.nodeId === value)) {
    throw new Error('Unknown administered node: no stored admin key for that node id');
  }
  envelope.selected = value;
  _writeEnvelope(envelope);
  return value;
}

/**
 * The selected *grant* (seed-free), or null when `self` is selected or the
 * selected entry has been removed.
 * @param {number} [now]
 * @returns {object|null}
 */
export function getSelectedAdminNode(now = Date.now()) {
  const envelope = _readEnvelope(now);
  if (!envelope || isSpecialSelection(envelope.selected)) return null;
  const record = envelope.entries.find((e) => e.nodeId === envelope.selected) ?? null;
  return record ? _publicEntry(record) : null;
}

/**
 * The selected grant while it is still valid, else null.
 *
 * This is NOT a "first non-expired entry" lookup: with no (or a `self`)
 * selection it returns null even when other grants are stored.
 * @param {number} [now] epoch millis
 * @returns {object|null}
 */
export function activeAdminNode(now = Date.now()) {
  const entry = getSelectedAdminNode(now);
  return entry && entry.expiresAt > now ? entry : null;
}

// ── Write accessors ───────────────────────────────────────────

/**
 * Add (or replace, by nodeId) an admin entry. Throws on invalid hex/lifetime.
 * The very first stored entry becomes the selection, so a freshly generated
 * key is usable without an extra click; afterwards the selection only changes
 * through `selectAdminNode`.
 *
 * @param {object} input
 * @param {string} input.nodeId Target node id (64 hex).
 * @param {string} input.adminSeedHex
 * @param {string} input.adminPubHex
 * @param {number} [input.grantedAt]
 * @param {number} [input.expiresAt] defaults to grantedAt + 7d.
 * @param {string|null} [input.label]
 * @param {string|null} [input.nodeAddr]
 * @param {string[]} [input.scopes] defaults to `['joins']`.
 * @returns {object} the seed-free stored entry
 */
export function addAdminEntry({
  nodeId,
  adminSeedHex,
  adminPubHex,
  grantedAt,
  expiresAt,
  label = null,
  nodeAddr = null,
  scopes = null,
} = {}) {
  const normalizedNodeId = _requireHex64(nodeId, HEX64_MESSAGE.nodeId);
  const normalizedSeed = _requireHex64(adminSeedHex, HEX64_MESSAGE.adminSeedHex);
  const normalizedPub = _requireHex64(adminPubHex, HEX64_MESSAGE.adminPubHex);
  const normalizedAddr = _requireNodeAddr(nodeAddr);

  const now = Date.now();
  const granted = grantedAt == null ? now : Number(grantedAt);
  const expires = expiresAt == null ? granted + DEFAULT_TTL_MS : Number(expiresAt);
  if (!Number.isFinite(granted)) throw new Error('grantedAt must be a finite timestamp');
  if (!Number.isFinite(expires)) throw new Error('expiresAt must be a finite timestamp');
  if (!(expires > granted)) throw new Error('expiresAt must be greater than grantedAt');

  const envelope = _readEnvelope(now) ?? { selected: null, entries: [] };
  const isFirstEntry = envelope.entries.length === 0;

  const record = {
    nodeId: normalizedNodeId,
    adminSeedHex: normalizedSeed,
    adminPubHex: normalizedPub,
    scope: 'admin',
    scopes: _normalizeScopes(scopes, V1_SCOPES),
    // A locally generated key carries a provisional TTL — `manual` until an
    // operator-signed bundle is imported.
    grantSource: GRANT_SOURCE.MANUAL,
    grantedAt: granted,
    expiresAt: expires,
    label: typeof label === 'string' ? label : null,
    nodeAddr: normalizedAddr,
    lastSeenStatus: null,
    lastSeenKind: null,
    lastSeenAddress: null,
    lastSeenAt: null,
  };

  const replaced = envelope.entries.some((e) => e.nodeId === normalizedNodeId);
  envelope.entries = envelope.entries.filter((e) => e.nodeId !== normalizedNodeId);
  envelope.entries.push(record);
  if (isFirstEntry && !replaced) envelope.selected = normalizedNodeId;

  _writeEnvelope(envelope);
  return _publicEntry(record);
}

/**
 * Apply a verified, node-operator-signed grant to an **existing** entry.
 *
 * Unlike `addAdminEntry`, this requires a stored key for `nodeId` (the seed is
 * never invented here) and strictly validates the scopes — a verified bundle
 * with unknown or empty scopes throws rather than falling back to joins-only.
 * It replaces `scopes`/`grantedAt`/`expiresAt`/`label`, marks the entry
 * `grantSource: 'bundle'`, and preserves the seed, public key, node address,
 * last-seen probe memory, and the current selection.
 *
 * @param {string} nodeId
 * @param {{ scopes: string[], grantedAt: number, expiresAt: number, label?: string|null }} grant
 * @returns {object} the seed-free stored entry
 */
export function applyAdminGrant(nodeId, { scopes, grantedAt, expiresAt, label = null } = {}) {
  const wanted = _requireHex64(nodeId, HEX64_MESSAGE.nodeId);
  const normalizedScopes = _requireScopes(scopes);

  const granted = Number(grantedAt);
  const expires = Number(expiresAt);
  if (!Number.isFinite(granted)) throw new Error('grantedAt must be a finite timestamp');
  if (!Number.isFinite(expires)) throw new Error('expiresAt must be a finite timestamp');
  if (!(expires > granted)) throw new Error('expiresAt must be greater than grantedAt');

  const envelope = _readEnvelope();
  const index = envelope ? envelope.entries.findIndex((e) => e.nodeId === wanted) : -1;
  if (index === -1) {
    throw new Error('generate a key for this node first');
  }

  const existing = envelope.entries[index];
  envelope.entries[index] = {
    // Preserve seed/public key/nodeAddr/lastSeen*; only the grant's meaning
    // (scopes, TTL, label, source) is replaced.
    ...existing,
    scopes: normalizedScopes,
    grantedAt: granted,
    expiresAt: expires,
    label: typeof label === 'string' ? label : null,
    grantSource: GRANT_SOURCE.BUNDLE,
  };
  // Selection is untouched: applying a bundle never changes the target.
  _writeEnvelope(envelope);
  return _publicEntry(envelope.entries[index]);
}

/**
 * Record what a probe/query last saw about an administered node. Unknown
 * fields are left untouched so a partial probe never erases better data.
 * @param {string} nodeId
 * @param {{ status?: string|null, kind?: string|null, address?: string|null, at?: number }} seen
 */
export function updateLastSeen(nodeId, { status = null, kind = null, address = null, at = null } = {}) {
  if (!_isHex64(nodeId)) return;
  const envelope = _readEnvelope();
  if (!envelope) return;
  const wanted = nodeId.toLowerCase();
  let touched = false;
  envelope.entries = envelope.entries.map((entry) => {
    if (entry.nodeId !== wanted) return entry;
    touched = true;
    return {
      ...entry,
      lastSeenStatus: status != null ? status : entry.lastSeenStatus,
      lastSeenKind: kind != null ? kind : entry.lastSeenKind,
      lastSeenAddress: address != null ? address : entry.lastSeenAddress,
      lastSeenAt: at != null ? at : entry.lastSeenAt,
    };
  });
  if (touched) _writeEnvelope(envelope);
}

/**
 * Remove a delegated admin key (no-op when absent). If it was the selection,
 * the selection falls back to `_defaultSelection` (another active grant, or
 * `self`) so the console never points at a removed node.
 * @param {string} nodeId
 */
export function removeAdminNode(nodeId) {
  if (typeof nodeId !== 'string') return;
  const wanted = nodeId.toLowerCase();
  const envelope = _readEnvelope();
  if (!envelope) return;
  envelope.entries = envelope.entries.filter((record) => record.nodeId !== wanted);
  if (envelope.selected === wanted) {
    envelope.selected = _defaultSelection(envelope.entries, Date.now());
  }
  _writeEnvelope(envelope);
}

/**
 * Remove every admin entry and reset the selection to `self`.
 * Best-effort.
 */
export function clearAllAdminEntries() {
  const store = _storage();
  if (store) {
    try {
      store.removeItem(STORE_KEY);
      store.removeItem(STORE_KEY_V1);
    } catch {
      /* ignore */
    }
  }
}

/**
 * The ONLY accessor that returns admin key material. Returns the exact 32-byte
 * seed for `nodeId`, or null when absent / invalid.
 * @param {string} nodeId
 * @returns {Uint8Array|null}
 */
export function adminSeedBytes(nodeId) {
  if (typeof nodeId !== 'string') return null;
  const wanted = nodeId.toLowerCase();
  const record = _readEnvelope()?.entries.find((entry) => entry.nodeId === wanted) ?? null;
  return record ? _hexToBytes(record.adminSeedHex) : null;
}
