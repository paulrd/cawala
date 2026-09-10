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

// ── Node / data state ─────────────────────────────────────────

/** @type {{ children: Array, accounts: Array, joinRequests: Array, activity: Array }} */
export const nodeState = $state({
  children: [],
  accounts: [],
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

// ── UI state ──────────────────────────────────────────────────

/** Mobile sidebar open state. */
export const uiState = $state({
  sidebarOpen: false,
});

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
  nodeState.joinRequests = [];
  nodeState.activity = [];
  Object.keys(loadingState).forEach((k) => (loadingState[k] = false));
  Object.keys(errorState).forEach((k) => (errorState[k] = null));
}
