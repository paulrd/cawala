import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Node-kind derivation (P1).
 *
 * The kind of a node is inferred from the child list of a topology snapshot.
 * Inference is one-way: when the snapshot does not say, the answer is
 * `unknown` — never a plausible-looking guess.
 */

const { NODE_KIND, inferNodeKind, kindLabel, childRoleLabel, kindBadgeVariant } = await import(
  '../src/lib/nodeKind.js'
);

const user = (id = 'u1') => ({ id, kind: 'user' });
const node = (id = 'n1') => ({ id, kind: 'node' });

// ── inferNodeKind ────────────────────────────────────────────────────────────

test('no children means unknown, not leaf', () => {
  assert.equal(inferNodeKind([]), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind(null), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind(undefined), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind('users'), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind({}), NODE_KIND.UNKNOWN);
});

test('a child list of only users makes the node a leaf', () => {
  assert.equal(inferNodeKind([user('a'), user('b')]), NODE_KIND.LEAF);
  assert.equal(inferNodeKind([user()]), NODE_KIND.LEAF);
});

test('one child node makes the node internal, whatever else it holds', () => {
  assert.equal(inferNodeKind([user(), node(), user()]), NODE_KIND.INTERNAL);
  assert.equal(inferNodeKind([node('a'), node('b')]), NODE_KIND.INTERNAL);
});

test('unrecognised or missing child kinds stay unknown', () => {
  assert.equal(inferNodeKind([{ id: 'x', kind: 'mystery' }]), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind([{ id: 'x' }]), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind([user(), { kind: 'mystery' }]), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind([null, undefined]), NODE_KIND.UNKNOWN);
});

test('malformed child entries never crash the inference', () => {
  // A hole in the child list degrades to `unknown` rather than guessing the
  // rest of the list is representative.
  assert.equal(inferNodeKind([user(), null]), NODE_KIND.UNKNOWN);
  assert.equal(inferNodeKind([null, undefined]), NODE_KIND.UNKNOWN);
  // An observed child node is still reported, hole or not.
  assert.equal(inferNodeKind([null, node()]), NODE_KIND.INTERNAL);
});

// ── Labels and badge variants ────────────────────────────────────────────────

test('every kind has an explicit, non-guessing label', () => {
  assert.equal(kindLabel('internal'), 'Internal node');
  assert.equal(kindLabel('leaf'), 'Leaf node');
  assert.equal(kindLabel('user'), 'User leaf');
  assert.equal(kindLabel('unknown'), 'Unknown kind');
  // Anything unrecognised (including empty) falls back to the honest label.
  assert.equal(kindLabel(null), 'Unknown kind');
  assert.equal(kindLabel(undefined), 'Unknown kind');
  assert.equal(kindLabel(''), 'Unknown kind');
  assert.equal(kindLabel('bridge'), 'Unknown kind');
});

test('child rows label their own kind', () => {
  assert.equal(childRoleLabel('node'), 'Child node');
  assert.equal(childRoleLabel('user'), 'User account');
  assert.equal(childRoleLabel('mystery'), 'Child');
  assert.equal(childRoleLabel(null), 'Child');
});

test('badge variants follow the kind palette', () => {
  assert.equal(kindBadgeVariant('internal'), 'info');
  assert.equal(kindBadgeVariant('leaf'), 'ok');
  assert.equal(kindBadgeVariant('user'), 'ok');
  assert.equal(kindBadgeVariant('unknown'), 'muted');
  assert.equal(kindBadgeVariant(null), 'muted');
  assert.equal(kindBadgeVariant('bridge'), 'muted');
});
