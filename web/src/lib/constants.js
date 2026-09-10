/** Cawala M4 — Constants */

/** Maximum children per node (decision 2: strict 8-cap at every level). */
export const MAX_CHILDREN = 8;

/** Slot indices for children. */
export const SLOT_RANGE = [0, 1, 2, 3, 4, 5, 6, 7];

/** Message type discriminators (matching crates/msg). */
export const MSG_TYPES = {
  /** Control: request to join. */
  JOIN_REQUEST: 0x01,
  /** Control: join approved (leaf issues address). */
  JOIN_APPROVED: 0x02,
  /** Control: join rejected. */
  JOIN_REJECTED: 0x03,
  /** Control: topology edit commands. */
  TOPO_CREATE_CHILD: 0x10,
  TOPO_MOVE_CHILD: 0x11,
  TOPO_DETACH_CHILD: 0x12,
  /** Ledger: issue/burn. */
  LEDGER_ADJUST: 0x20,
  /** Ledger: transfer. */
  LEDGER_TRANSFER: 0x21,
  /** Ack/status responses. */
  ACK: 0xf0,
};

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
