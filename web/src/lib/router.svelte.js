/**
 * Cawala M4 — Lightweight hash-based router.
 *
 * Uses window.location.hash (#/path). No external dependencies.
 * Provides a reactive `currentRoute` that Svelte components can read.
 */

import { ROUTES } from './constants.js';

/** @type {string} */
let _currentRoute = $state(parseRoute());

/** @type {Array<() => void>} */
const _listeners = [];

function parseRoute() {
  const hash = window.location.hash || '#/';
  return hash.slice(1) || '/';
}

function notify() {
  _currentRoute = parseRoute();
  for (const fn of _listeners) fn();
}

/**
 * Get the current route reactively (Svelte 5 rune).
 * Use inside components: `$: route = currentRoute()`
 * Actually — we expose a getter function so components can call it in $derived.
 */
export function currentRoute() {
  return _currentRoute;
}

/**
 * Subscribe to route changes. Returns unsubscribe function.
 * For use outside Svelte (e.g. api.js polling).
 */
export function onRouteChange(fn) {
  _listeners.push(fn);
  return () => {
    const i = _listeners.indexOf(fn);
    if (i >= 0) _listeners.splice(i, 1);
  };
}

/**
 * Navigate to a route.
 * @param {string} path
 */
export function navigate(path) {
  window.location.hash = '#' + path;
}

/**
 * Check if a route is active (exact or prefix match).
 * @param {string} route - The nav item's route.
 * @param {string} current - The current route.
 * @param {boolean} [exact=false]
 * @returns {boolean}
 */
export function isActive(route, current, exact = false) {
  if (exact) return current === route;
  if (route === '/') return current === '/';
  return current === route || current.startsWith(route + '/');
}

/**
 * Initialize the router. Call once from App.svelte onMount.
 * Attaches the hashchange listener.
 */
export function initRouter() {
  window.addEventListener('hashchange', notify);
  // Also handle initial state
  notify();
}

/**
 * Destroy the router (for cleanup / testing).
 */
export function destroyRouter() {
  window.removeEventListener('hashchange', notify);
  _listeners.length = 0;
}
