import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Admin target chain + lock gate (R6/R7, P4).
 *
 * `api.js` imports the Svelte rune stores and the `?raw` policy module, so the
 * rune primitive, storage and the raw loader are shimmed before it loads. Admin
 * mode defaults to mock, which is enough to exercise the real lock/target state
 * machine without wasm:
 *   - locked: no ancestor chain, no bounds, no stepping, writes throw;
 *   - unlocked: `discover_admin_targets` yields a 2-level chain and the up/down
 *     control steps it, clamped at both ends;
 *   - designate/revoke/topology replies map to their documented shapes.
 *
 * The actual wasm `admin_*` calls (and their dropped `node_addr` argument) are
 * covered by the build/wasm surface; here we lock down the JS request mapping.
 */

class MemoryStorage {
  #map = new Map();
  getItem(key) {
    return this.#map.has(key) ? this.#map.get(key) : null;
  }
  setItem(key, value) {
    this.#map.set(key, String(value));
  }
  removeItem(key) {
    this.#map.delete(key);
  }
  clear() {
    this.#map.clear();
  }
}

const memory = new MemoryStorage();
globalThis.localStorage = memory;
globalThis.window = { localStorage: memory };
globalThis.$state = (value) => value;

const {
  getAdminTargets,
  adminTargetBounds,
  stepAdminTarget,
  setAdministeredNode,
  getAdministeredNode,
  discoverAdminTargets,
  unlockAdmin,
  lockAdminMode,
  adminPolicyInfo,
  adminDesignate,
  adminRevoke,
  getAdministrators,
  adminDetachChild,
  adminMoveChild,
  approveJoin,
  rejectJoin,
  redeliverJoin,
  adminIssue,
  adminBurn,
} = await import('../src/lib/api.js');

const CHILD = 'c1'.repeat(32);
const OTHER = 'd2'.repeat(32);

async function unlock() {
  lockAdminMode();
  return unlockAdmin();
}

// ── locked by default ────────────────────────────────────────────────────────

test('admin is locked by default: no targets, no bounds, no stepping', () => {
  lockAdminMode();
  assert.deepEqual(getAdminTargets(), []);
  assert.equal(adminTargetBounds(), null);
  assert.equal(stepAdminTarget(1), null);
  assert.equal(stepAdminTarget(-1), null);
  assert.equal(setAdministeredNode(1), null);

  const view = getAdministeredNode();
  assert.equal(view.nodeId, 'self');
  assert.equal(view.isSelf, true);
});

test('every admin write refuses while locked', async () => {
  lockAdminMode();
  const writes = [
    () => adminDesignate(CHILD),
    () => adminRevoke(CHILD),
    () => adminDetachChild(CHILD),
    () => adminMoveChild(CHILD, 1),
    () => adminIssue(CHILD, 5, 'reason'),
    () => adminBurn(CHILD, 5, 'reason'),
    () => approveJoin(CHILD),
    () => rejectJoin(CHILD),
    () => redeliverJoin(CHILD),
  ];
  for (const write of writes) {
    await assert.rejects(write, /locked/i);
  }
});

// ── unlock + discovery ───────────────────────────────────────────────────────

test('unlocking acknowledges the policy and discovers the ancestor chain', async () => {
  const result = await unlock();
  assert.equal(result.targets.length, 2);
  assert.equal(result.acknowledgementCurrent, false, 'first acknowledgement');

  const info = adminPolicyInfo();
  assert.equal(info.acknowledgedHash, info.hash);
  assert.equal(info.acknowledgementCurrent, true);

  const targets = getAdminTargets();
  assert.deepEqual(
    targets.map((t) => t.depth),
    [1, 2],
  );
  assert.deepEqual(
    targets.map((t) => t.node),
    ['mock', 'mock-root'],
  );
  // The synthetic walk reaches the root, so the top crumb is the true root.
  assert.deepEqual(
    targets.map((t) => t.isRoot),
    [false, true],
  );
  // getAdminTargets returns copies, not the live cache.
  targets[0].depth = 99;
  assert.equal(getAdminTargets()[0].depth, 1);
});

// ── stepping / bounds / selection ────────────────────────────────────────────

test('the up/down control steps the chain and clamps at both ends', async () => {
  await unlock();
  assert.deepEqual(adminTargetBounds(), { current: 1, min: 1, max: 2, count: 2 });

  const up = stepAdminTarget(1);
  assert.equal(up.depth, 2);
  assert.equal(up.node, 'mock-root');
  assert.equal(adminTargetBounds().current, 2);
  assert.equal(getAdministeredNode().depth, 2);

  assert.equal(stepAdminTarget(1), null, 'root is the top');
  assert.equal(adminTargetBounds().current, 2, 'a refused step does not move');

  const down = stepAdminTarget(-1);
  assert.equal(down.depth, 1);
  assert.equal(adminTargetBounds().current, 1);
  assert.equal(stepAdminTarget(-1), null, 'the direct parent is the bottom');
});

test('setAdministeredNode selects a valid depth and rejects unknown ones', async () => {
  await unlock();

  const selected = setAdministeredNode(2);
  assert.equal(selected.depth, 2);
  assert.equal(getAdministeredNode().depth, 2);

  assert.equal(setAdministeredNode(99), null, 'unknown depth is refused');
  assert.equal(getAdministeredNode().depth, 2, 'a refused selection keeps the current one');
  assert.equal(setAdministeredNode(0), null);
  assert.equal(setAdministeredNode(1).depth, 1);
});

test('rediscovery replaces the chain and re-clamps the selection', async () => {
  await unlock();
  setAdministeredNode(2);

  const targets = await discoverAdminTargets();
  assert.equal(targets.length, 2);
  assert.ok(targets.some((t) => t.depth === 2), 'depth 2 still exists');
});

// ── designate / revoke / topology request mapping ────────────────────────────

test('getAdministrators surfaces the node-reported designation set', async () => {
  await unlock();
  const admins = await getAdministrators();
  assert.deepEqual(admins, ['z6MkHs7Kj3xVnR5pQw9bYf2dLg8mC4tEa6uIiOoPp']);

  // A returned copy, never the live mock array.
  admins.push('mutated');
  assert.deepEqual(await getAdministrators(), ['z6MkHs7Kj3xVnR5pQw9bYf2dLg8mC4tEa6uIiOoPp']);
});

test('nodeState.admins holds the fetched set and clears on lock', async () => {
  await unlock();
  const { nodeState } = await import('../src/lib/stores.svelte.js');
  nodeState.admins = await getAdministrators();
  assert.deepEqual(nodeState.admins, ['z6MkHs7Kj3xVnR5pQw9bYf2dLg8mC4tEa6uIiOoPp']);

  lockAdminMode();
  assert.deepEqual(nodeState.admins, [], 'locking clears the reported set');
});

test('designate and revoke echo the child and default to the selected target', async () => {
  await unlock();
  assert.deepEqual(await adminDesignate(CHILD), { status: 'designated', child: CHILD });
  assert.deepEqual(await adminRevoke(CHILD), { status: 'revoked', child: CHILD });

  // An explicit target overrides the selected ancestor (still accepted).
  assert.deepEqual(await adminDesignate(CHILD, OTHER), {
    status: 'designated',
    child: CHILD,
  });
});

test('topology/value actions map to their documented shapes', async () => {
  await unlock();

  assert.deepEqual(await adminMoveChild(CHILD), {
    status: 'moved',
    child: CHILD,
    slot: null,
  });
  assert.deepEqual(await adminMoveChild(CHILD, 3), {
    status: 'moved',
    child: CHILD,
    slot: 3,
  });
  assert.deepEqual(await adminDetachChild(CHILD), { status: 'detached', child: CHILD });

  assert.equal((await approveJoin(CHILD)).status, 'approved');
  assert.equal((await rejectJoin(CHILD)).status, 'rejected');
  assert.equal((await redeliverJoin(CHILD)).status, 'redelivered');

  const issued = await adminIssue(CHILD, 10, 'top-up');
  assert.equal(issued.status, 'applied');
  assert.equal(issued.direction, 'issue');
  const burned = await adminBurn(CHILD, 10, 'write-off');
  assert.equal(burned.status, 'applied');
  assert.equal(burned.direction, 'burn');
});

// ── lock clears the chain and re-gates writes ────────────────────────────────

test('locking clears the chain, bounds and selection again', async () => {
  await unlock();
  assert.equal(getAdminTargets().length, 2);

  lockAdminMode();
  assert.deepEqual(getAdminTargets(), []);
  assert.equal(adminTargetBounds(), null);
  assert.equal(stepAdminTarget(1), null);
  assert.equal(getAdministeredNode().isSelf, true);
  await assert.rejects(() => adminRevoke(CHILD), /locked/i);
});
