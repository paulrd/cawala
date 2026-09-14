/** Cawala M4 — Constants */

/** Maximum children per node (decision 2: strict 8-cap at every level). */
export const MAX_CHILDREN = 8;

/** Slot indices for children. */
export const SLOT_RANGE = [0, 1, 2, 3, 4, 5, 6, 7];

/**
 * Mock/UI-only message type discriminators.
 *
 * WARNING: these numeric values do NOT match any Rust wire enum. The live
 * control surface does not ride `send_envelope`; it uses the dedicated
 * `cawala/control/0` ALPN. These constants are retained so existing imports
 * keep working, but do not treat them as the wire format. Use ENVELOPE_ACK,
 * JOIN_STATE, JOIN_OUTCOME, and CONTROL_EVENT below for live status strings.
 */
export const MSG_TYPES = {
  /** Mock/UI-only: request to join. */
  JOIN_REQUEST: 0x01,
  /** Mock/UI-only: join approved (leaf issues address). */
  JOIN_APPROVED: 0x02,
  /** Mock/UI-only: join rejected. */
  JOIN_REJECTED: 0x03,
  /** Mock/UI-only: topology edit commands. */
  TOPO_CREATE_CHILD: 0x10,
  TOPO_MOVE_CHILD: 0x11,
  TOPO_DETACH_CHILD: 0x12,
  /** Mock/UI-only: ledger issue/burn. */
  LEDGER_ADJUST: 0x20,
  /** Mock/UI-only: ledger transfer. */
  LEDGER_TRANSFER: 0x21,
  /** Mock/UI-only: ack/status responses. */
  ACK: 0xf0,
};

/**
 * Real envelope acknowledgement buckets returned by the live wasm
 * `ClientNode.send_envelope` (Rust `cawala-msg` wire ack status).
 */
export const ENVELOPE_ACK = {
  DELIVERED: 'delivered',
  DUPLICATE: 'duplicate',
  REJECTED: 'rejected',
};

/** Real join-handshake states from the live wasm `JoinStatus.state`. */
export const JOIN_STATE = {
  NONE: 'none',
  PENDING: 'pending',
  JOINED: 'joined',
  REJECTED: 'rejected',
};

/** Real immediate `JoinOutcome.status` buckets from the live wasm client. */
export const JOIN_OUTCOME = {
  PENDING: 'pending',
  REJECTED: 'rejected',
};

/** Real kinds of control events drained from the live wasm control loop. */
export const CONTROL_EVENT = {
  ACCEPTED: 'accepted',
  REJECTED: 'rejected',
};

/**
 * Real kinds of ledger events drained from the live wasm ledger loop
 * (`LedgerEventDto.kind`).
 */
export const LEDGER_EVENT = {
  ORDER_RESULT: 'order_result',
  BALANCE_RECEIPT: 'balance_receipt',
  INVALID: 'invalid',
};

/**
 * Real terminal order statuses from the live wasm ledger (`LedgerEventDto.status`,
 * Rust `OrderStatusV1`).
 */
export const ORDER_STATUS = {
  APPLIED: 'applied',
  DUPLICATE: 'duplicate',
  PARTIAL: 'partial',
  REJECTED: 'rejected',
  INDETERMINATE: 'indeterminate',
};

/**
 * Stable order-rejection reasons surfaced on a rejected `order_result`
 * (`LedgerEventDto.reason`, Rust `OrderRejectV1`).
 */
export const ORDER_REJECT = {
  UNAUTHORIZED: 'unauthorized',
  BAD_REQUEST: 'bad_request',
  EXPIRED: 'expired',
  INSUFFICIENT_BALANCE: 'insufficient_balance',
  ACCOUNT_NOT_OPENED: 'account_not_opened',
  NOT_A_CHILD: 'not_a_child',
  INTERNAL: 'internal',
};

/** ALPN the live browser control client speaks to its parent node. */
export const CONTROL_ALPN = 'cawala/control/0';

/** Connection status values. */
export const CONNECTION = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
};

/** Client lifecycle states. */
export const CLIENT_STATUS = {
  BOOTING: 'booting',
  READY: 'ready',
  ERROR: 'error',
};

/** Route definitions (hash-based). */
export const ROUTES = {
  DASHBOARD: '/',
  MY_NODE: '/node',
  CHILDREN: '/node/children',
  ACCOUNTS: '/accounts',
  ACTIVITY: '/activity',
  JOINS: '/node/joins',
  MY_ACCOUNT: '/account',
  SETTINGS: '/settings',
  JOIN_FLOW: '/join',
  DEBUG: '/debug',
};

/** Navigation items for sidebar / mobile nav. */
export const NAV_ITEMS = [
  { route: ROUTES.DASHBOARD, label: 'Dashboard', icon: 'grid' },
  { route: ROUTES.JOIN_FLOW, label: 'Join', icon: 'log-in' },
  { route: ROUTES.MY_NODE, label: 'My Node', icon: 'server' },
  { route: ROUTES.ACCOUNTS, label: 'Accounts', icon: 'wallet' },
  { route: ROUTES.ACTIVITY, label: 'Activity', icon: 'list' },
  { route: ROUTES.JOINS, label: 'Join Requests', icon: 'user-plus' },
  { route: ROUTES.MY_ACCOUNT, label: 'My Account', icon: 'user' },
  { route: ROUTES.SETTINGS, label: 'Settings', icon: 'settings' },
];

/** Activity entry types. */
export const ACTIVITY_TYPES = {
  TRANSFER: 'transfer',
  ISSUE: 'issue',
  BURN: 'burn',
  JOIN_APPROVED: 'join_approved',
  JOIN_REJECTED: 'join_rejected',
  TOPO_CREATE: 'topo_create',
  TOPO_MOVE: 'topo_move',
  TOPO_DETACH: 'topo_detach',
};

/** Map activity types to human-readable labels. */
export const ACTIVITY_LABELS = {
  [ACTIVITY_TYPES.TRANSFER]: 'Transfer',
  [ACTIVITY_TYPES.ISSUE]: 'Issue',
  [ACTIVITY_TYPES.BURN]: 'Burn',
  [ACTIVITY_TYPES.JOIN_APPROVED]: 'Join Approved',
  [ACTIVITY_TYPES.JOIN_REJECTED]: 'Join Rejected',
  [ACTIVITY_TYPES.TOPO_CREATE]: 'Child Created',
  [ACTIVITY_TYPES.TOPO_MOVE]: 'Child Moved',
  [ACTIVITY_TYPES.TOPO_DETACH]: 'Child Detached',
};
