/**
 * Cawala M4 — Svelte 5 rune-based state stores.
 *
 * All global UI state lives here. Components import and read/write directly.
 * No external state library needed.
 */

import { CONNECTION, CLIENT_STATUS } from './constants.js';

// ── Client state ──────────────────────────────────────────────

/** @type {{ status: string, endpointId: string, address: string|null, connectionStatus: string, error: string|null }} */
export const clientState = $state({
  status: CLIENT_STATUS.BOOTING,
  endpointId: '',
  address: null,
  connectionStatus: CONNECTION.DISCONNECTED,
  error: null,
});

// ── Live-mode capabilities & control events ──────────────────

/** @type {{ mock: boolean, canAdmin: boolean, canQueryPeers: boolean, canQueryNode: boolean, identityPersistent: boolean, multiTabLeader: boolean, multiTabWarning: string|null }} */
export const apiCapabilities = $state({
  mock: true,
  canAdmin: false,
  canQueryPeers: false,
  canQueryNode: false,
  identityPersistent: false,
  multiTabLeader: false,
  multiTabWarning: null,
});

/** Last control event drained from the wasm poller. */
export const lastControlEvent = $state({ value: null });

/**
 * Live verified-ledger state, updated by the api.js ledger-event poller.
 *
 * `balance`/`height`/`pinnedLedger` mirror the wasm `ledger_status()`; `activity`
 * is the JS-side UI-shaped transfer list built from drained ledger events
 * (capped like the Rust `MAX_ACTIVITY_ENTRIES`); `pending` counts in-flight
 * orders; `verifiedAt` is the local ms timestamp of the last verified receipt.
 * An `invalid` ledger event sets `error` and never mutates `balance`.
 *
 * @type {{ balance: number|null, height: number|null, pinnedLedger: string|null, activity: Array, pending: number, verifiedAt: number|null, error: string|null }}
 */
export const ledgerState = $state({
  balance: null,
  height: null,
  pinnedLedger: null,
  activity: [],
  pending: 0,
  verifiedAt: null,
  error: null,
});

// ── Node / data state ─────────────────────────────────────────

/** @type {{ children: Array, accounts: Array, accountsTruncated: boolean, joinRequests: Array, activity: Array }} */
export const nodeState = $state({
  children: [],
  accounts: [],
  // Whether the node's ledger view reported its account-row cap was hit.
  accountsTruncated: false,
  joinRequests: [],
  activity: [],
});

/** Loading flags (keyed by data domain). */
export const loadingState = $state({
  children: false,
  accounts: false,
  joinRequests: false,
  activity: false,
  node: false,
});

/** Error messages (keyed by data domain). */
export const errorState = $state({
  children: null,
  accounts: null,
  joinRequests: null,
  activity: null,
  node: null,
});

// ── Administered node (selected node context) ────────────────

/**
 * The node every admin screen is scoped to.
 *
 * `nodeId` is `'self'` (this browser's own node), a granted node id, or null
 * before the api layer has resolved a selection. `kind`/`address`/`status`
 * come from the last successful probe of that node, never from a guess.
 *
 * @type {{ nodeId: string|null, isSelf: boolean, label: string|null, nodeAddr: string|null, scopes: Array<string>, grantExpiresAt: number|null, kind: string, status: string, address: string|null, lastSeenAt: number|null, childrenCount: number|null, mock: boolean }}
 */
export const administeredNode = $state({
  nodeId: null,
  isSelf: true,
  label: null,
  nodeAddr: null,
  scopes: [],
  grantExpiresAt: null,
  kind: 'unknown',
  status: 'unknown',
  address: null,
  lastSeenAt: null,
  childrenCount: null,
  mock: false,
});

/** @type {{ mock: boolean, canQueryNode: boolean, canAdminister: boolean, scopes: { joins: boolean, topology: boolean, value: boolean } }} */
export const adminCapabilities = $state({
  mock: false,
  canQueryNode: false,
  canAdminister: false,
  scopes: { joins: false, topology: false, value: false },
});

/**
 * Replace the administered-node view in place (keeps one reactive object).
 * @param {Partial<typeof administeredNode>} view
 */
export function applyAdministeredNode(view) {
  Object.assign(administeredNode, view);
}

/**
 * Incremented every time the administered node actually changes.
 *
 * Pages read this in their load `$effect`s so a target switch refetches
 * instead of leaving the previous target's rows on screen.
 *
 * @type {{ value: number }}
 */
export const targetEpoch = $state({ value: 0 });

/** Bump after the selection changed (api layer calls this). */
export function bumpTargetEpoch() {
  targetEpoch.value += 1;
}

/**
 * Capability flags derived from the selection. `canQueryNode` is true when
 * admin reads can run for the selected node (mock always can; live needs a
 * selected, non-expired grant). Per-scope flags stay P2-shaped so pages can
 * gate controls without re-deriving them.
 * @param {{ mock?: boolean, canQueryNode?: boolean, canAdminister?: boolean, scopes?: object }} caps
 */
export function applyAdminCapabilities(caps) {
  Object.assign(adminCapabilities, caps);
}

// ── UI state ──────────────────────────────────────────────────

/**
 * Mobile sidebar open state.
 *
 * `dialogOpen`/`writeInFlight` lock the node selector so a target switch can
 * never redirect an in-flight confirmation or write. `selectorOwner` keeps a
 * single dropdown open when both the context bar and the mobile chip exist.
 */
export const uiState = $state({
  sidebarOpen: false,
  dialogOpen: false,
  writeInFlight: false,
  selectorOwner: null, // null | 'bar' | 'chip'
});

/**
 * Mark a privileged write as in flight (locks node switching).
 * @param {boolean} value
 */
export function setWriteInFlight(value) {
  uiState.writeInFlight = !!value;
}

// ── Toast notifications ───────────────────────────────────────

/** @type {Array<{ id: string, message: string, variant: string, timestamp: number }>} */
let _toasts = $state([]);

/** Expose as a getter so components can iterate. */
export function getToasts() {
  return _toasts;
}

/**
 * Show a toast notification.
 * @param {string} message
 * @param {string} [variant='info'] - 'info' | 'ok' | 'warn' | 'danger'
 * @param {number} [duration=4000] - Auto-dismiss ms (0 = manual).
 * @returns {string} Toast ID for manual dismiss.
 */
export function showToast(message, variant = 'info', duration = 4000) {
  const id = Math.random().toString(36).slice(2, 10);
  const toast = { id, message, variant, timestamp: Date.now() };
  _toasts = [..._toasts, toast];
  if (duration > 0) {
    setTimeout(() => dismissToast(id), duration);
  }
  return id;
}

/**
 * Dismiss a toast by ID.
 * @param {string} id
 */
export function dismissToast(id) {
  _toasts = _toasts.filter((t) => t.id !== id);
}

// ── Helpers ───────────────────────────────────────────────────

/** Reset all data state (e.g. on disconnect). */
export function resetDataState() {
  nodeState.children = [];
  nodeState.accounts = [];
  nodeState.accountsTruncated = false;
  nodeState.joinRequests = [];
  nodeState.activity = [];
  Object.keys(loadingState).forEach((k) => (loadingState[k] = false));
  Object.keys(errorState).forEach((k) => (errorState[k] = null));
}
