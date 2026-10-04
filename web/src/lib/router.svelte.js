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
 * The single route from `routes` that best matches `current`, or null.
 *
 * A route matches on an exact hit or when it is a path-prefix ancestor
 * (`/node` matches `/node/children`). `/` only matches exactly. When both a
 * parent and a more specific item match, the longest route wins, so the parent
 * section is not also shown as active (e.g. `/node/joins` selects
 * `/node/joins`, not `/node`).
 *
 * @param {ReadonlyArray<string>} routes
 * @param {string} current
 * @returns {string|null}
 */
export function activeNavRoute(routes, current) {
  let best = null;
  for (const route of routes) {
    const matches =
      route === current || (route !== '/' && current.startsWith(route + '/'));
    if (matches && (best === null || route.length > best.length)) best = route;
  }
  return best;
}

/**
 * Initialize the router. Call once from App.svelte onMount.
 * Attaches the hashchange listener.
 */
export function initRouter() {
  window.addEventListener('hashchange', notify);
  // Legacy routes from before the single Admin page (R8): `#/node`,
  // `#/node/joins`, … all land there instead of on a 404.
  const legacy = parseRoute();
  if (legacy === '/node' || legacy.startsWith('/node/')) {
    window.location.hash = '#' + ROUTES.ADMIN;
  }
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
