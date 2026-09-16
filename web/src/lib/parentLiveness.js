/**
 * Cawala M5 — passive parent-liveness tracker (informational only).
 *
 * Automated foster-parent recovery was deliberately cut (see
 * `.slim/deepwork/m5-foster-recovery.md`). What remains is a **passive,
 * informational** signal with no authority and no gating: this module records
 * only whether the last parent-facing probe succeeded or failed so the UI can
 * show a "parent unreachable" notice. It never performs a recovery action —
 * the UI reuses `leave()` plus the existing join flow for that.
 *
 * Storage key `cawala.recovery.v1`, shape:
 *   { v: 1, parent: string, firstFailureAt: number|null,
 *     lastOkAt: number|null, consecutiveFailures: number }
 *
 * Semantics (per recorded parent):
 *   - failed probe  → increment `consecutiveFailures`, set `firstFailureAt`
 *                     if unset (last success is preserved in `lastOkAt`);
 *   - successful probe → clear failures (`consecutiveFailures = 0`,
 *                     `firstFailureAt = null`) and stamp `lastOkAt`;
 *   - recorded parent changes → the old record is ignored/reset.
 *
 * Storage is resolved like `adminKeys.js` and every read/write is best-effort:
 * SSR, private mode, quota, or a throwing `localStorage` yield a neutral
 * "reachable" status instead of throwing.
 *
 * The reducer functions (`applyProbe`, `trackerStatus`, `normalizeTracker`)
 * are pure so they can be exercised in Node without a DOM.
 */

export const PARENT_TRACKER_KEY = 'cawala.recovery.v1';
export const PARENT_TRACKER_VERSION = 1;

/**
 * The exact, frozen `parentStatus()` key order consumed by the UI lane.
 * @type {ReadonlyArray<string>}
 */
export const PARENT_STATUS_KEYS = Object.freeze([
  'parent',
  'reachable',
  'lastOkAt',
  'unreachableSince',
  'consecutiveFailures',
]);

/**
 * @param {unknown} value
 * @returns {number|null} a finite epoch-ms timestamp, or null
 */
function _timestamp(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return null;
}

/**
 * A fresh, empty tracker record for `parent`.
 * @param {string|null} [parent]
 * @returns {{ v: number, parent: string|null, firstFailureAt: number|null, lastOkAt: number|null, consecutiveFailures: number }}
 */
export function emptyTracker(parent = null) {
  return {
    v: PARENT_TRACKER_VERSION,
    parent: parent ?? null,
    firstFailureAt: null,
    lastOkAt: null,
    consecutiveFailures: 0,
  };
}

/**
 * Validate + normalize a raw stored tracker. Returns null for anything
 * malformed or written by an unknown version, so a bad row is ignored rather
 * than allowed to corrupt the status.
 *
 * @param {unknown} raw
 * @returns {{ v: number, parent: string, firstFailureAt: number|null, lastOkAt: number|null, consecutiveFailures: number }|null}
 */
export function normalizeTracker(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  if (raw.v !== PARENT_TRACKER_VERSION) return null;
  if (typeof raw.parent !== 'string' || raw.parent.length === 0) return null;

  const consecutiveFailures =
    Number.isInteger(raw.consecutiveFailures) && raw.consecutiveFailures >= 0
      ? raw.consecutiveFailures
      : 0;
  const firstFailureAt = _timestamp(raw.firstFailureAt);
  const lastOkAt = _timestamp(raw.lastOkAt);

  // A failing record must know since when; otherwise the status invariant
  // (`unreachableSince` is non-null while `reachable` is false) cannot hold.
  if (consecutiveFailures > 0 && firstFailureAt === null) return null;

  return {
    v: PARENT_TRACKER_VERSION,
    parent: raw.parent,
    firstFailureAt,
    lastOkAt,
    consecutiveFailures,
  };
}

/**
 * Pure reducer: fold one parent probe outcome into the tracker state.
 *
 * A changed parent starts a fresh record, so a failure recorded against a
 * previous parent never colours the new one. Never mutates `previous`.
 *
 * @param {unknown} previous Stored tracker (may be null/malformed).
 * @param {string|null} parent The parent that was probed.
 * @param {boolean} ok Whether the probe reached the parent.
 * @param {number} [now] Epoch ms of the probe.
 * @returns {{ v: number, parent: string|null, firstFailureAt: number|null, lastOkAt: number|null, consecutiveFailures: number }}
 */
export function applyProbe(previous, parent, ok, now = Date.now()) {
  const at = Number.isFinite(now) ? now : Date.now();
  let state = normalizeTracker(previous);
  if (!state || parent == null || state.parent !== parent) {
    state = emptyTracker(parent ?? null);
  }
  if (ok) {
    state.lastOkAt = at;
    state.firstFailureAt = null;
    state.consecutiveFailures = 0;
  } else {
    if (state.firstFailureAt == null) state.firstFailureAt = at;
    state.consecutiveFailures += 1;
  }
  return state;
}

/**
 * A neutral status for a parent with no recorded failures (also used when the
 * record is absent, stale, or storage is unavailable).
 * @param {string|null} parent
 * @returns {{ parent: string|null, reachable: boolean, lastOkAt: number|null, unreachableSince: number|null, consecutiveFailures: number }}
 */
export function emptyParentStatus(parent = null) {
  return {
    parent: parent ?? null,
    reachable: true,
    lastOkAt: null,
    unreachableSince: null,
    consecutiveFailures: 0,
  };
}

/**
 * Pure projection of a stored tracker to the frozen `parentStatus()` shape.
 *
 * Returns a neutral status when there is no record, when `currentParent` is
 * unknown, or when the recorded parent no longer matches — i.e. a parent change
 * resets/ignores the old record.
 *
 * @param {unknown} previous
 * @param {string|null} currentParent
 * @returns {{ parent: string|null, reachable: boolean, lastOkAt: number|null, unreachableSince: number|null, consecutiveFailures: number }}
 */
export function trackerStatus(previous, currentParent) {
  const parent = typeof currentParent === 'string' && currentParent.length > 0 ? currentParent : null;
  const state = normalizeTracker(previous);
  if (!state || parent === null || state.parent !== parent) {
    return emptyParentStatus(parent);
  }
  return {
    parent: state.parent,
    reachable: state.consecutiveFailures === 0,
    lastOkAt: state.lastOkAt,
    unreachableSince: state.consecutiveFailures > 0 ? state.firstFailureAt : null,
    consecutiveFailures: state.consecutiveFailures,
  };
}

/**
 * Resolve a localStorage-like object, or null when storage is unavailable
 * (SSR, private mode, quota, workers). Never throws. Mirrors `adminKeys.js`.
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
 * Read the raw stored tracker, or null when absent/unreadable/malformed.
 * Best-effort: never throws.
 * @returns {object|null}
 */
export function loadTracker() {
  const store = _storage();
  if (!store) return null;
  let raw = null;
  try {
    raw = store.getItem(PARENT_TRACKER_KEY);
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Persist a tracker record. `null` removes the key. Best-effort: never throws.
 * @param {object|null} state
 */
export function saveTracker(state) {
  const store = _storage();
  if (!store) return;
  try {
    if (state == null) store.removeItem(PARENT_TRACKER_KEY);
    else store.setItem(PARENT_TRACKER_KEY, JSON.stringify(state));
  } catch {
    /* ignore */
  }
}

/**
 * Record one parent probe outcome. A no-op when `parent` is unknown; storage
 * failures are swallowed. Returns the resulting tracker state (or null when
 * nothing was recorded).
 *
 * @param {string|null} parent
 * @param {boolean} ok
 * @param {number} [now]
 * @returns {object|null}
 */
export function recordParentProbe(parent, ok, now = Date.now()) {
  if (typeof parent !== 'string' || parent.length === 0) return null;
  const next = applyProbe(loadTracker(), parent, !!ok, now);
  saveTracker(next);
  return next;
}

/**
 * The frozen informational status for `currentParent`.
 * @param {string|null} currentParent
 * @returns {{ parent: string|null, reachable: boolean, lastOkAt: number|null, unreachableSince: number|null, consecutiveFailures: number }}
 */
export function getParentStatus(currentParent) {
  return trackerStatus(loadTracker(), currentParent);
}
