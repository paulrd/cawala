/**
 * Cawala — pure view helpers for the ancestor target switcher and the admin
 * context bar (no DOM, no storage, no wasm: Node-testable).
 *
 * Admin targets come from the api layer's ancestor walk: a flat list of
 * `{ node, address, depth }` where `depth` 1 is this browser's direct parent
 * and the last entry is the root. There is no dropdown anymore (R7): the UI
 * steps up/down that chain, so the helpers here only describe positions,
 * labels and badges on it.
 */

import { truncateMiddle } from './utils.js';

/** Selection values that name this browser / the synthetic mock node. */
export const SELF_ID = 'self';
export const MOCK_ID = 'mock';

/** Target statuses the console can show. */
export const ADMIN_STATUS = {
  MOCK: 'mock',
  SELF: 'self',
  ACTIVE: 'active',
  UNREACHABLE: 'unreachable',
  UNKNOWN: 'unknown',
};

/** Badge copy for one status. Grounded labels only: no "connected" claims. */
const STATUS_BADGES = {
  mock: { variant: 'info', label: 'Mock mode' },
  active: { variant: 'ok', label: 'Active' },
  unreachable: { variant: 'warn', label: 'Unreachable' },
  self: { variant: 'muted', label: 'This browser' },
  unknown: { variant: 'muted', label: 'Unknown' },
};

/**
 * @param {string} status
 * @returns {{ variant: string, label: string }}
 */
export function statusBadge(status) {
  return STATUS_BADGES[status] || STATUS_BADGES.unknown;
}

/**
 * Short, stable display id (`z6MkHs7…ta2doK`).
 * @param {string} id
 * @returns {string}
 */
export function shortId(id) {
  return id ? truncateMiddle(id, 6) : '';
}

/**
 * What one depth in the chain is called. Depth 1 is this browser's parent; the
 * deepest entry is the root only when the walk actually reached it. The walk
 * deliberately stops at the first undesignated hop (`discover_admin_targets`),
 * so a truncated top is labelled "Top of chain" rather than falsely "Root".
 *
 * @param {number} depth 1-based depth above this browser
 * @param {number} maxDepth depth of the reachable top
 * @param {boolean} [topIsRoot] whether the `maxDepth` entry is the true root
 * @returns {string}
 */
export function depthLabel(depth, maxDepth, topIsRoot = false) {
  if (depth === 1) return 'Parent';
  if (depth === maxDepth) return topIsRoot ? 'Root' : 'Top of chain';
  return `Level ${depth}`;
}

/**
 * One row of the ancestor path breadcrumb: the crumbs run from this browser up
 * to the highest reachable ancestor, and exactly one is marked `current`.
 *
 * @param {Array<{ node: string, address: string|null, depth: number, isRoot?: boolean }>} targets
 * @param {number|null} currentDepth the selected target's depth
 * @returns {Array<{ depth: number, node: string, address: string|null, isRoot: boolean, label: string, current: boolean }>}
 */
export function buildAncestorPath(targets = [], currentDepth = null) {
  const list = [...(targets || [])].sort((a, b) => a.depth - b.depth);
  const maxDepth = list.length ? list[list.length - 1].depth : 0;
  return list.map((target) => ({
    depth: target.depth,
    node: target.node,
    address: target.address ?? null,
    isRoot: Boolean(target.isRoot),
    label: depthLabel(target.depth, maxDepth, Boolean(target.isRoot)),
    current: currentDepth === target.depth,
  }));
}

/**
 * Whether the up/down control may step in `delta` (`+1` = up towards the root,
 * `-1` = down towards this browser). Disabled at both ends of the chain.
 *
 * @param {number|null} currentDepth
 * @param {number} delta
 * @param {Array<{ depth: number }>} targets
 * @returns {boolean}
 */
export function canStepTarget(currentDepth, delta, targets = []) {
  if (currentDepth == null) return false;
  const depths = (targets || []).map((t) => t.depth).sort((a, b) => a - b);
  if (depths.length === 0) return false;
  const next = currentDepth + delta;
  return depths.includes(next);
}

/**
 * Whether the value-reason validation error should be shown: only once the
 * field has been touched **and** is still invalid. Pure, so it is unit-testable.
 * @param {boolean} touched
 * @param {boolean} valid
 * @returns {boolean}
 */
export function valueReasonErrorVisible(touched, valid) {
  return Boolean(touched) && !valid;
}
