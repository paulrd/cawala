import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Selector / context-bar view model (P1).
 *
 * These helpers turn stored grants + target state into the rows the shared
 * `AdminNodeRow` renders. Copy must stay grounded: a badge never claims a
 * connection it has not observed, and a kind is only ever shown when a probe
 * actually recorded one.
 */

const {
  SELF_ID,
  MOCK_ID,
  ADMIN_STATUS,
  statusBadge,
  shortId,
  grantToItem,
  buildSelectorItems,
  needsGrantBanner,
} = await import('../src/lib/adminView.js');

const NOW = 1_800_000_000_000;
const NODE_A = 'a1'.repeat(32);
const NODE_B = 'b2'.repeat(32);

function grant(overrides = {}) {
  return {
    nodeId: NODE_A,
    adminPubHex: 'e5'.repeat(32),
    scope: 'admin',
    scopes: ['joins'],
    grantedAt: NOW - 1000,
    expiresAt: NOW + 6 * 24 * 3600 * 1000,
    label: null,
    nodeAddr: null,
    lastSeenStatus: null,
    lastSeenKind: null,
    lastSeenAddress: null,
    lastSeenAt: null,
    active: true,
    ...overrides,
  };
}

// ── statusBadge ──────────────────────────────────────────────────────────────

test('statuses carry grounded labels — never a claim of connectivity', () => {
  const expected = {
    [ADMIN_STATUS.ACTIVE]: 'Active',
    [ADMIN_STATUS.EXPIRED]: 'Expired',
    [ADMIN_STATUS.UNREACHABLE]: 'Unreachable',
    [ADMIN_STATUS.REVOKED]: 'Revoked',
    [ADMIN_STATUS.NO_GRANT]: 'No admin key',
    [ADMIN_STATUS.SELF]: 'This browser',
    [ADMIN_STATUS.MOCK]: 'Mock mode',
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

test('banner-worthy statuses are the ones that need attention', () => {
  for (const status of [
    ADMIN_STATUS.EXPIRED,
    ADMIN_STATUS.UNREACHABLE,
    ADMIN_STATUS.REVOKED,
    ADMIN_STATUS.NO_GRANT,
  ]) {
    assert.equal(needsGrantBanner(status), true, status);
  }
  for (const status of [
    ADMIN_STATUS.ACTIVE,
    ADMIN_STATUS.SELF,
    ADMIN_STATUS.MOCK,
    ADMIN_STATUS.UNKNOWN,
    'flying',
  ]) {
    assert.equal(needsGrantBanner(status), false, status);
  }
});

// ── shortId / formatTtl feeding the rows ─────────────────────────────────────

test('shortId trims a node id to a stable head and tail', () => {
  assert.equal(shortId(NODE_A), 'a1a1a1\u2026a1a1a1');
  assert.equal(shortId(''), '');
  assert.equal(shortId(null), '');
  assert.equal(shortId('short'), 'short', 'short values are left alone');
});

// ── grantToItem ──────────────────────────────────────────────────────────────

test('an active grant renders Active with its ttl and scopes', () => {
  const item = grantToItem(grant({ label: 'Home node', nodeAddr: '203.0.113.7' }), { now: NOW });
  assert.equal(item.id, NODE_A);
  assert.equal(item.label, 'Home node');
  assert.equal(item.sublabel, shortId(NODE_A));
  assert.equal(item.status, ADMIN_STATUS.ACTIVE);
  assert.equal(item.statusBadge.label, 'Active');
  assert.equal(item.ttl, '6d left');
  assert.equal(item.nodeAddr, '203.0.113.7');
  assert.deepEqual(item.scopes, ['joins']);
  assert.equal(item.disabled, false);
  assert.equal(item.isSelf, false);
});

test('a probe that saw "unreachable" is shown as unreachable, not active', () => {
  const item = grantToItem(grant({ lastSeenStatus: 'unreachable' }), { now: NOW });
  assert.equal(item.status, ADMIN_STATUS.UNREACHABLE);
  assert.equal(item.statusBadge.label, 'Unreachable');
  assert.equal(needsGrantBanner(item.status), true);
});

test('an expired grant is disabled and labelled Expired', () => {
  const item = grantToItem(grant({ active: false, expiresAt: NOW - 1 }), { now: NOW });
  assert.equal(item.status, ADMIN_STATUS.EXPIRED);
  assert.equal(item.ttl, 'expired');
  assert.equal(item.disabled, true);
});

test('kind and label are only shown when they were actually observed', () => {
  const unknown = grantToItem(grant(), { now: NOW });
  assert.equal(unknown.kind, null, 'no probe -> no kind');
  assert.equal(unknown.kindLabel, '');
  assert.equal(unknown.kindVariant, 'muted');
  assert.equal(unknown.label, shortId(NODE_A), 'unlabelled grants fall back to the id');

  const observed = grantToItem(grant({ lastSeenKind: 'internal' }), { now: NOW });
  assert.equal(observed.kind, 'internal');
  assert.equal(observed.kindLabel, 'Internal node');
  assert.equal(observed.kindVariant, 'info');

  const forged = grantToItem(grant({ lastSeenKind: 'bridge' }), { now: NOW });
  assert.equal(forged.kindLabel, 'Unknown kind', 'unrecognised kinds are not named');
});

// ── buildSelectorItems ───────────────────────────────────────────────────────

test('groups are context first, then granted, then expired', () => {
  const nodes = [
    grant({ nodeId: NODE_A, active: true }),
    grant({ nodeId: NODE_B, active: false, expiresAt: NOW - 1 }),
  ];
  const { groups } = buildSelectorItems({
    self: { endpointId: 'c7'.repeat(32) },
    mock: false,
    nodes,
    selected: NODE_A,
    now: NOW,
  });

  assert.deepEqual(
    groups.map((g) => g.id),
    ['context', 'granted', 'expired'],
  );
  assert.equal(groups[0].items.length, 1);
  assert.equal(groups[0].items[0].id, SELF_ID);
  assert.equal(groups[0].items[0].label, 'This browser');
  assert.equal(groups[0].items[0].status, ADMIN_STATUS.SELF);
  assert.equal(groups[0].items[0].selected, false);

  assert.deepEqual(groups[1].items.map((i) => i.id), [NODE_A]);
  assert.equal(groups[1].items[0].selected, true);
  assert.deepEqual(groups[2].items.map((i) => i.id), [NODE_B]);
  assert.equal(groups[2].items[0].selected, false);
});

test('empty state is just this browser — no phantom groups', () => {
  const { groups } = buildSelectorItems({ mock: false, nodes: [], selected: SELF_ID, now: NOW });
  assert.equal(groups.length, 1);
  assert.equal(groups[0].id, 'context');
  assert.equal(groups[0].items.length, 1);
  assert.equal(groups[0].items[0].id, SELF_ID);
  assert.equal(groups[0].items[0].selected, true);
});

test('mock mode adds the synthetic node to the context group', () => {
  const { groups } = buildSelectorItems({ mock: true, nodes: [], selected: null, now: NOW });
  const ids = groups[0].items.map((i) => i.id);
  assert.deepEqual(ids, [SELF_ID, MOCK_ID]);
  assert.equal(groups[0].items[0].status, ADMIN_STATUS.MOCK, 'self reads as Mock mode');
  assert.equal(groups[0].items[1].status, ADMIN_STATUS.MOCK);
  assert.equal(groups[0].items[1].label, 'Mock node');
  assert.equal(groups.length, 1, 'the mock node does not open a granted group');
});

test('a selection pointing at a removed grant marks nothing as selected', () => {
  const { groups } = buildSelectorItems({
    mock: false,
    nodes: [grant({ nodeId: NODE_A, active: true })],
    selected: 'f'.repeat(64),
    now: NOW,
  });
  const selected = groups.flatMap((g) => g.items).filter((i) => i.selected);
  assert.deepEqual(selected, []);
});
