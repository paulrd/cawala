/**
 * Cawala — delegated admin key store (L5a, client-side only).
 *
 * A user leaf can be granted delegated admin authority (K_admin) over a parent
 * node's joins. The generated admin seed is device-local key material: it is
 * persisted here (never in any exported identity bundle) and handed to the wasm
 * client via `api.configureAdminNode()` → `ClientNode.set_admin_key()`.
 *
 * Storage key `cawala.admin.v1`, shape:
 *   { v: 1, entries: [ { nodeId, adminSeedHex, adminPubHex, scope: 'admin',
 *                        grantedAt, expiresAt, label } ] }
 *
 * Every public accessor except `adminSeedBytes()` returns seed-free views, so
 * accidental logging/serialization can never leak K_admin. Pure ESM, no DOM
 * beyond localStorage, dependency-free and Node-testable.
 */

const ADMIN_KEY = 'cawala.admin.v1';
const ADMIN_STORAGE_VERSION = 1;
const DEFAULT_TTL_MS = 7 * 24 * 3600 * 1000;

const HEX64 = /^[0-9a-f]{64}$/i;
const HEX64_MESSAGE = {
  nodeId: 'nodeId must be exactly 64 hex characters',
  adminSeedHex: 'adminSeedHex must be exactly 64 hex characters',
  adminPubHex: 'adminPubHex must be exactly 64 hex characters',
};

/**
 * Resolve a localStorage-like object, or null when storage is unavailable
 * (SSR, private mode, quota, workers). Never throws.
 * @returns {Storage|null}
 */
function _storage() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) return window.localStorage;
  } catch {
    /* ignore */
  }
  try {
    if (typeof globalThis !== 'undefined' && globalThis.localStorage) {
      return globalThis.localStorage;
    }
  } catch {
    /* ignore */
  }
  return null;
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function _isHex64(value) {
  return typeof value === 'string' && HEX64.test(value);
}

/**
 * @param {unknown} value
 * @param {string} message
 * @returns {string} lowercase hex
 */
function _requireHex64(value, message) {
  if (!_isHex64(value)) throw new Error(message);
  return value.toLowerCase();
}

/**
 * @param {string} hex
 * @returns {Uint8Array}
 */
function _hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/**
 * Seed-free view of a stored record.
 * @param {object} record
 */
function _publicEntry(record) {
  return {
    nodeId: record.nodeId,
    adminPubHex: record.adminPubHex,
    scope: record.scope,
    grantedAt: record.grantedAt,
    expiresAt: record.expiresAt,
    label: record.label,
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
    grantedAt,
    expiresAt,
    label: typeof entry.label === 'string' ? entry.label : null,
  };
}

/**
 * Read the persisted records (including seeds). Internal only — never exported.
 * Malformed/unavailable storage yields an empty list.
 * @returns {Array<object>}
 */
function _readRecords() {
  const store = _storage();
  if (!store) return [];
  let raw = null;
  try {
    raw = store.getItem(ADMIN_KEY);
  } catch {
    return [];
  }
  if (!raw) return [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    parsed.v !== ADMIN_STORAGE_VERSION ||
    !Array.isArray(parsed.entries)
  ) {
    return [];
  }
  const records = [];
  for (const entry of parsed.entries) {
    const record = _normalizeStored(entry);
    if (record) records.push(record);
  }
  return records;
}

/**
 * Persist records. Best-effort: unavailable/full storage is a silent no-op.
 * @param {Array<object>} records
 */
function _writeRecords(records) {
  const store = _storage();
  if (!store) return;
  try {
    if (records.length === 0) {
      store.removeItem(ADMIN_KEY);
    } else {
      store.setItem(ADMIN_KEY, JSON.stringify({ v: ADMIN_STORAGE_VERSION, entries: records }));
    }
  } catch {
    /* ignore */
  }
}

/**
 * All stored admin entries as seed-free objects. Malformed/unavailable storage
 * yields `[]`; never throws.
 * @returns {Array<{ nodeId: string, adminPubHex: string, scope: 'admin', grantedAt: number, expiresAt: number, label: string|null }>}
 */
export function loadAdminEntries() {
  return _readRecords().map(_publicEntry);
}

/**
 * UI-facing list of admin nodes with an `active` flag. Never returns the seed.
 * @param {number} [now] epoch millis
 * @returns {Array<{ nodeId: string, adminPubHex: string, scope: 'admin', grantedAt: number, expiresAt: number, label: string|null, active: boolean }>}
 */
export function listAdminNodes(now = Date.now()) {
  return _readRecords().map((record) => ({
    nodeId: record.nodeId,
    adminPubHex: record.adminPubHex,
    scope: record.scope,
    grantedAt: record.grantedAt,
    expiresAt: record.expiresAt,
    label: record.label,
    active: record.expiresAt > now,
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
  const record = _readRecords().find((entry) => entry.nodeId === wanted);
  return record ? _publicEntry(record) : null;
}

/**
 * The first non-expired admin entry (seed-free), or null.
 * @param {number} [now] epoch millis
 * @returns {object|null}
 */
export function activeAdminNode(now = Date.now()) {
  const record = _readRecords().find((entry) => entry.expiresAt > now);
  return record ? _publicEntry(record) : null;
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
  const record = _readRecords().find((entry) => entry.nodeId === wanted);
  if (!record) return null;
  return _hexToBytes(record.adminSeedHex);
}

/**
 * Add (or replace, by nodeId) an admin entry. Throws on invalid hex/length or
 * non-positive lifetime. Best-effort persistence when storage is unavailable.
 * @param {object} input
 * @param {string} input.nodeId
 * @param {string} input.adminSeedHex
 * @param {string} input.adminPubHex
 * @param {number} [input.grantedAt] epoch millis (defaults to now)
 * @param {number} [input.expiresAt] epoch millis (defaults to grantedAt + 7d)
 * @param {string|null} [input.label]
 * @returns {object} the seed-free stored entry
 */
export function addAdminEntry({
  nodeId,
  adminSeedHex,
  adminPubHex,
  grantedAt,
  expiresAt,
  label = null,
} = {}) {
  const normalizedNodeId = _requireHex64(nodeId, HEX64_MESSAGE.nodeId);
  const normalizedSeed = _requireHex64(adminSeedHex, HEX64_MESSAGE.adminSeedHex);
  const normalizedPub = _requireHex64(adminPubHex, HEX64_MESSAGE.adminPubHex);

  const now = Date.now();
  const granted = grantedAt == null ? now : Number(grantedAt);
  const expires = expiresAt == null ? granted + DEFAULT_TTL_MS : Number(expiresAt);
  if (!Number.isFinite(granted)) throw new Error('grantedAt must be a finite timestamp');
  if (!Number.isFinite(expires)) throw new Error('expiresAt must be a finite timestamp');
  if (!(expires > granted)) throw new Error('expiresAt must be greater than grantedAt');

  const record = {
    nodeId: normalizedNodeId,
    adminSeedHex: normalizedSeed,
    adminPubHex: normalizedPub,
    scope: 'admin',
    grantedAt: granted,
    expiresAt: expires,
    label: typeof label === 'string' ? label : null,
  };

  const records = _readRecords().filter((entry) => entry.nodeId !== normalizedNodeId);
  records.push(record);
  _writeRecords(records);
  return _publicEntry(record);
}

/**
 * Remove the admin entry for `nodeId` (no-op when absent).
 * @param {string} nodeId
 */
export function removeAdminNode(nodeId) {
  if (typeof nodeId !== 'string') return;
  const wanted = nodeId.toLowerCase();
  const records = _readRecords().filter((entry) => entry.nodeId !== wanted);
  _writeRecords(records);
}

/**
 * Remove every admin entry. Best-effort.
 */
export function clearAllAdminEntries() {
  _writeRecords([]);
}
