/**
 * Cawala — pure view helpers for the administered-node selector and context
 * bar (no DOM, no storage, no wasm: Node-testable).
 */

import { kindLabel, kindBadgeVariant } from './nodeKind.js';
import { truncateMiddle, formatTtl } from './utils.js';

/** Selection values that name this browser / the synthetic mock node. */
export const SELF_ID = 'self';
export const MOCK_ID = 'mock';

/** Grant/target statuses the console can show. */
export const ADMIN_STATUS = {
  MOCK: 'mock',
  SELF: 'self',
  ACTIVE: 'active',
  EXPIRED: 'expired',
  UNREACHABLE: 'unreachable',
  REVOKED: 'revoked',
  NO_GRANT: 'no-grant',
  UNKNOWN: 'unknown',
};

/** Badge copy for one status. Grounded labels only: no "connected" claims. */
const STATUS_BADGES = {
  mock: { variant: 'info', label: 'Mock mode' },
  active: { variant: 'ok', label: 'Active' },
  expired: { variant: 'danger', label: 'Expired' },
  unreachable: { variant: 'warn', label: 'Unreachable' },
  revoked: { variant: 'danger', label: 'Revoked' },
  'no-grant': { variant: 'warn', label: 'No admin key' },
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
 * One row in the node selector.
 * @param {object} item
 */
function toItem({ id, label, sublabel = '', kind = null, status, nodeAddr = null, grantedAt = null, expiresAt = null, scopes = [], grantSource = null, isSelf = false, selected = false, now }) {
  return {
    id,
    label,
    sublabel,
    kind,
    kindLabel: kind ? kindLabel(kind) : '',
    kindVariant: kind ? kindBadgeVariant(kind) : 'muted',
    status,
    statusBadge: statusBadge(status),
    nodeAddr,
    grantedAt,
    ttl: expiresAt ? formatTtl(expiresAt, now) : '',
    expiresAt,
    scopes,
    grantSource,
    // `bundle` scopes/TTL are operator-signed (truthful); `manual` is a local
    // provisional grant. No badge when there is no grant at all (self/mock).
    sourceBadge: sourceBadge(grantSource),
    isSelf,
    selected,
    disabled: status === ADMIN_STATUS.EXPIRED,
  };
}

/**
 * Badge for where a grant's scopes/TTL came from, or null when there is no
 * grant (self / mock rows).
 * @param {string|null} grantSource
 * @returns {{ variant: string, label: string }|null}
 */
export function sourceBadge(grantSource) {
  if (grantSource === 'bundle') return { variant: 'ok', label: 'Operator-signed' };
  if (grantSource === 'manual') return { variant: 'warn', label: 'Provisional' };
  return null;
}

/**
 * Normalize one stored grant (a `listAdministeredNodes()` row) into the row
 * shape `AdminNodeRow` renders. Used by both the selector and Settings so the
 * two surfaces can never drift apart.
 *
 * @param {object} node
 * @param {{ selected?: boolean, now?: number }} [opts]
 * @returns {object}
 */
export function grantToItem(node, { selected = false, now = Date.now() } = {}) {
  return toItem({
    id: node.nodeId,
    label: node.label || shortId(node.nodeId),
    sublabel: shortId(node.nodeId),
    kind: node.lastSeenKind || null,
    status: node.active
      ? node.lastSeenStatus === 'unreachable'
        ? ADMIN_STATUS.UNREACHABLE
        : ADMIN_STATUS.ACTIVE
      : ADMIN_STATUS.EXPIRED,
    nodeAddr: node.nodeAddr,
    grantedAt: node.grantedAt ?? null,
    expiresAt: node.expiresAt,
    scopes: node.scopes || [],
    grantSource: node.grantSource ?? 'manual',
    selected,
    now,
  });
}

/**
 * Build the selector's grouped item list: this browser (always), the mock
 * pseudo-node (mock mode only), active grants, then expired grants.
 *
 * @param {object} input
 * @param {{ endpointId?: string, label?: string }} [input.self] this browser's node
 * @param {boolean} input.mock
 * @param {Array<object>} input.nodes stored grants (`listAdministeredNodes()`)
 * @param {string|null} input.selected current selection id
 * @param {number} [input.now]
 * @returns {{ groups: Array<{ id: string, label: string, items: Array<object> }> }}
 */
export function buildSelectorItems({ self = {}, mock = false, nodes = [], selected = null, now = Date.now() }) {
  const selfItem = toItem({
    id: SELF_ID,
    label: 'This browser',
    sublabel: shortId(self.endpointId || ''),
    status: mock ? ADMIN_STATUS.MOCK : ADMIN_STATUS.SELF,
    isSelf: true,
    selected: selected === SELF_ID,
    now,
  });

  const groups = [{ id: 'context', label: 'This browser', items: [selfItem] }];

  if (mock) {
    groups[0].items.push(
      toItem({
        id: MOCK_ID,
        label: 'Mock node',
        sublabel: 'synthetic data',
        kind: 'internal',
        status: ADMIN_STATUS.MOCK,
        selected: selected === MOCK_ID,
        now,
      }),
    );
  }

  const active = [];
  const expired = [];
  for (const node of nodes) {
    const item = grantToItem(node, { selected: selected === node.nodeId, now });
    (node.active ? active : expired).push(item);
  }

  if (active.length > 0) groups.push({ id: 'granted', label: 'Granted nodes', items: active });
  if (expired.length > 0) groups.push({ id: 'expired', label: 'Expired', items: expired });

  return { groups };
}

/**
 * Which grant/target states deserve a banner in the context bar.
 * @param {string} status
 * @returns {boolean}
 */
export function needsGrantBanner(status) {
  return (
    status === ADMIN_STATUS.EXPIRED ||
    status === ADMIN_STATUS.UNREACHABLE ||
    status === ADMIN_STATUS.REVOKED ||
    status === ADMIN_STATUS.NO_GRANT
  );
}
