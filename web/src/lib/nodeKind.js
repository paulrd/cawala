/**
 * Cawala — node-kind model (pure, dependency-free, Node-testable).
 *
 * A node's kind is inferred from the child list of a topology snapshot
 * (`AdminQuery` -> `AdminSnapshotDto.node.children`, or this client's own
 * `local_snapshot().children`). Each child carries `kind: "node" | "user"`:
 *
 *   - any child of kind `node`  -> the target has children *nodes*: internal
 *   - every child of kind `user`-> the target only holds user accounts: leaf
 *   - no children / unknown kinds -> unknown (never guessed)
 *
 * `user` is not produced by that inference: it is this client's own role (a
 * browser user leaf), which is known directly rather than read from a child
 * list it does not have. See `api.js` `_selfKind`.
 *
 * An authoritative `role` field on the node record is a later, additive
 * change; P1 inference is deliberately one-way and never invents a kind.
 */

/** Node kinds as they flow through the UI. */
export const NODE_KIND = {
  INTERNAL: 'internal',
  LEAF: 'leaf',
  /** This client's own role: a browser user leaf (never inferred). */
  USER: 'user',
  UNKNOWN: 'unknown',
};

/** Human labels for each kind (badge + header copy). */
const NODE_KIND_LABELS = {
  internal: 'Internal node',
  leaf: 'Leaf node',
  user: 'User leaf',
  unknown: 'Unknown kind',
};

/** Human labels for one child row, per child kind. */
const CHILD_ROLE_LABELS = {
  node: 'Child node',
  user: 'User account',
};

/**
 * Infer the kind of the node that owns `children`.
 *
 * @param {Array<{kind?: string}>|null|undefined} children
 * @returns {'internal'|'leaf'|'unknown'}
 */
export function inferNodeKind(children) {
  if (!Array.isArray(children) || children.length === 0) return NODE_KIND.UNKNOWN;
  if (children.some((c) => c && c.kind === 'node')) return NODE_KIND.INTERNAL;
  if (children.every((c) => c && c.kind === 'user')) return NODE_KIND.LEAF;
  return NODE_KIND.UNKNOWN;
}

/**
 * Badge label for a node kind. Unknown kinds fall back to the explicit
 * "Unknown kind" label rather than a plausible-sounding guess.
 * @param {string|null|undefined} kind
 * @returns {string}
 */
export function kindLabel(kind) {
  return NODE_KIND_LABELS[kind] || NODE_KIND_LABELS.unknown;
}

/**
 * Row label for one child, per its `kind` (`node` | `user`).
 * @param {string|null|undefined} childKind
 * @returns {string}
 */
export function childRoleLabel(childKind) {
  return CHILD_ROLE_LABELS[childKind] || 'Child';
}

/**
 * Badge variant for a node kind, reusing the shared Badge palette.
 * @param {string|null|undefined} kind
 * @returns {'info'|'ok'|'muted'}
 */
export function kindBadgeVariant(kind) {
  if (kind === NODE_KIND.INTERNAL) return 'info';
  if (kind === NODE_KIND.LEAF || kind === NODE_KIND.USER) return 'ok';
  return 'muted';
}
