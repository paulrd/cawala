import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Ancestor target-switcher view helpers (P4).
 *
 * Admin targets are a flat ancestor chain `{ node, address, depth }` (depth 1 =
 * this browser's direct parent, the last entry = the root). These helpers only
 * describe positions, labels and badges on that chain — there is no dropdown
 * and no grant data anymore.
 */

const {
  SELF_ID,
  MOCK_ID,
  ADMIN_STATUS,
  statusBadge,
  shortId,
  depthLabel,
  buildAncestorPath,
  canStepTarget,
  valueReasonErrorVisible,
} = await import('../src/lib/adminView.js');

const NODE_A = 'a1'.repeat(32);
const NODE_B = 'b2'.repeat(32);

const CHAIN = [
  { node: NODE_A, address: '0.3.1', depth: 1, isRoot: false },
  { node: NODE_B, address: '0.3', depth: 2, isRoot: false },
  { node: 'root'.padEnd(64, '0'), address: '0', depth: 3, isRoot: true },
];

// The same chain as seen when the walk stopped at the first undesignated hop:
// the top is the highest reachable ancestor, NOT the root.
const TRUNCATED_CHAIN = [
  { node: NODE_A, address: '0.3.1', depth: 1, isRoot: false },
  { node: NODE_B, address: '0.3', depth: 2, isRoot: false },
];

// ── identity / status constants ──────────────────────────────────────────────

test('view identity constants are stable', () => {
  assert.equal(SELF_ID, 'self');
  assert.equal(MOCK_ID, 'mock');
  assert.deepEqual(ADMIN_STATUS, {
    MOCK: 'mock',
    SELF: 'self',
    ACTIVE: 'active',
    UNREACHABLE: 'unreachable',
    UNKNOWN: 'unknown',
  });
});

// ── statusBadge ──────────────────────────────────────────────────────────────

test('statuses carry grounded labels — never a claim of connectivity', () => {
  const expected = {
    [ADMIN_STATUS.ACTIVE]: 'Active',
    [ADMIN_STATUS.UNREACHABLE]: 'Unreachable',
    [ADMIN_STATUS.MOCK]: 'Mock mode',
    [ADMIN_STATUS.SELF]: 'This browser',
    [ADMIN_STATUS.UNKNOWN]: 'Unknown',
  };
  for (const [status, label] of Object.entries(expected)) {
    assert.equal(statusBadge(status).label, label);
  }

  // Unknown statuses degrade to an explicit label instead of inventing one.
  assert.equal(statusBadge('flying').label, 'Unknown');
  assert.equal(statusBadge(null).label, 'Unknown');

  for (const status of Object.values(ADMIN_STATUS)) {
    const { label } = statusBadge(status);
    assert.ok(!/connected/i.test(label), `"${label}" must not imply a connection`);
  }
});

// ── shortId ──────────────────────────────────────────────────────────────────

test('shortId trims a node id to a stable head and tail', () => {
  assert.equal(shortId(NODE_A), 'a1a1a1\u2026a1a1a1');
  assert.equal(shortId(''), '');
  assert.equal(shortId(null), '');
  assert.equal(shortId('short'), 'short', 'short values are left alone');
});

// ── depthLabel ───────────────────────────────────────────────────────────────

test('depthLabel names the ends of the chain and numbers the middle', () => {
  assert.equal(depthLabel(1, 3), 'Parent');
  assert.equal(depthLabel(2, 3), 'Level 2');
  // The top is "Root" only when the walk actually reached the root.
  assert.equal(depthLabel(3, 3, true), 'Root');
  assert.equal(depthLabel(3, 3, false), 'Top of chain');
  assert.equal(depthLabel(3, 3), 'Top of chain', 'truncated by default');
  // A single-level chain is just the parent, never "Root".
  assert.equal(depthLabel(1, 1), 'Parent');
  assert.equal(depthLabel(1, 0), 'Parent');
});

// ── buildAncestorPath ────────────────────────────────────────────────────────

test('buildAncestorPath labels and orders the chain with one current crumb', () => {
  const path = buildAncestorPath(CHAIN, 2);
  assert.deepEqual(
    path.map((crumb) => crumb.depth),
    [1, 2, 3],
    'sorted by depth',
  );
  assert.deepEqual(
    path.map((crumb) => crumb.label),
    ['Parent', 'Level 2', 'Root'],
  );
  assert.deepEqual(
    path.map((crumb) => crumb.isRoot),
    [false, false, true],
  );
  assert.equal(path[1].current, true);
  assert.equal(path[0].current, false);
  assert.equal(path[2].current, false);
  assert.equal(path[0].node, NODE_A);
  assert.equal(path[0].address, '0.3.1');
});

test('buildAncestorPath labels a truncated top as "Top of chain", never "Root"', () => {
  const path = buildAncestorPath(TRUNCATED_CHAIN, 2);
  assert.deepEqual(
    path.map((crumb) => crumb.label),
    ['Parent', 'Top of chain'],
  );
  assert.equal(path[1].isRoot, false);
  assert.ok(!path.some((crumb) => crumb.label === 'Root'));
});

test('buildAncestorPath tolerates unordered input, missing addresses and empties', () => {
  const unordered = [
    { node: NODE_B, address: null, depth: 2 },
    { node: NODE_A, address: undefined, depth: 1 },
  ];
  const path = buildAncestorPath(unordered, 1);
  assert.deepEqual(
    path.map((crumb) => crumb.depth),
    [1, 2],
  );
  assert.equal(path[0].address, null, 'undefined address normalizes to null');

  assert.deepEqual(buildAncestorPath(), []);
  assert.deepEqual(buildAncestorPath(null, 1), []);
});

// ── canStepTarget ────────────────────────────────────────────────────────────

test('canStepTarget allows steps that land on a real depth only', () => {
  // From the direct parent, up to the next level is allowed, down is not.
  assert.equal(canStepTarget(1, +1, CHAIN), true);
  assert.equal(canStepTarget(1, -1, CHAIN), false);
  // From the root, only downwards.
  assert.equal(canStepTarget(3, +1, CHAIN), false);
  assert.equal(canStepTarget(3, -1, CHAIN), true);
  // Missing selection / empty chain never steps.
  assert.equal(canStepTarget(null, +1, CHAIN), false);
  assert.equal(canStepTarget(1, +1, []), false);
  assert.equal(canStepTarget(1, +1, null), false);
  // A hole in the chain is not steppable either.
  assert.equal(canStepTarget(1, +2, CHAIN), true, 'a landing on depth 3 is valid');
  assert.equal(
    canStepTarget(1, +1, [{ depth: 1 }, { depth: 5 }]),
    false,
    'depth 2 is absent',
  );
});

// ── valueReasonErrorVisible ──────────────────────────────────────────────────

test('valueReasonErrorVisible only shows after touch and while invalid', () => {
  assert.equal(valueReasonErrorVisible(false, false), false);
  assert.equal(valueReasonErrorVisible(false, true), false);
  assert.equal(valueReasonErrorVisible(true, true), false);
  assert.equal(valueReasonErrorVisible(true, false), true);
  assert.equal(valueReasonErrorVisible(undefined, false), false);
});
