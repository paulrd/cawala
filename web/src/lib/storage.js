/**
 * Cawala — localStorage classification (R1).
 *
 * The node is the source of truth for account/ledger/admin state. Browser
 * storage is layered, and this module is the single, documented place that
 * says which keys are allowed to be discarded and which are not. Every
 * storage touch in `api.js` should be read against this table.
 *
 * Three classes
 * -------------
 * - **authoritative-local** — must not be discarded. Losing these loses
 *   information the node cannot re-supply (the identity seed) or resets a
 *   trust decision that must be explicitly re-established (the TOFU anchors).
 *     - `cawala.identity.v1` — the Ed25519 transport seed (one browser
 *       install == one identity). Mnemonic-derived on new installs; a legacy
 *       random seed present here is preserved, never silently rekeyed.
 *     - `cawala.user-identity.v1` — the R3 user identity record (EIP-55
 *       address, the derived secp256k1 secret used to sign V4 orders,
 *       passkey-enrollment flag, provenance). The **mnemonic is never
 *       stored**; the record is persisted so a reload needs no unlock, and
 *       losing it forgets this device's user identity *and* drops the
 *       passkey-wrap binding that cannot be re-created without the phrase.
 *     - the TOFU anchors `pinned_ledger` / `pinned_leaf_keys` — carried *inside*
 *       the `cawala.ledger.v1` blob today (no key of their own). They are the
 *       authoritative-local trust pins a settlement proof must verify under.
 *
 * - **best-effort cache** — absence is tolerated. These blobs let a reload
 *   reconstruct local intent (pending orders, outbound join) without a network
 *   source, but a missing or corrupt blob must never block boot; boot proceeds
 *   with empty local state and re-validates balance/height from the node.
 *     - `cawala.state.v1:<nodeId>`
 *     - `cawala.ledger.v1:<nodeId>`
 *   The legacy un-suffixed `cawala.state.v1` / `cawala.ledger.v1` keys are also
 *   best-effort cache, read once as a backward-compat fallback.
 *
 * - **non-authoritative local** — never a source of truth; purely local
 *   bookkeeping that is safe to drop.
 *     - `cawala.recovery.v1` — passive parent-liveness tracker.
 *     - `cawala.admin.policy.v1` — acknowledged admin-policy hash.
 *     - `cawala.value.pending.v1` — in-flight value-op write journal
 *       (idempotency retry key).
 *
 * The functions here are pure/best-effort and never throw, so they can be
 * exercised on plain Node without a DOM.
 */

/** The three storage classes. */
export const STORAGE_CLASS = Object.freeze({
  /** Must not be discarded: identity seed + TOFU anchors. */
  AUTHORITATIVE_LOCAL: 'authoritative-local',
  /** Absence tolerated: reload-reconstruction blobs. */
  BEST_EFFORT_CACHE: 'best-effort-cache',
  /** Never a source of truth: local bookkeeping only. */
  NON_AUTHORITATIVE_LOCAL: 'non-authoritative-local',
});

/** Exact storage keys (scoped ones are suffixed with `:<nodeId>`). */
export const STORAGE_KEYS = Object.freeze({
  IDENTITY: 'cawala.identity.v1',
  USER_IDENTITY: 'cawala.user-identity.v1',
  STATE: 'cawala.state.v1',
  LEDGER: 'cawala.ledger.v1',
  RECOVERY: 'cawala.recovery.v1',
  ADMIN_POLICY: 'cawala.admin.policy.v1',
  VALUE_PENDING: 'cawala.value.pending.v1',
});

/**
 * The TOFU trust anchors. They have no localStorage key of their own: they are
 * fields inside the `cawala.ledger.v1` blob, and are authoritative-local.
 */
export const TOFU_ANCHOR_FIELDS = Object.freeze(['pinned_ledger', 'pinned_leaf_keys']);

/**
 * The full classification table, one row per logical key. `storage` names the
 * blob a field is carried inside when it is not a key of its own.
 *
 * @type {ReadonlyArray<{ key: string, class: string, scope: 'global'|'identity'|'blob-field', storage?: string, description: string }>}
 */
export const STORAGE_CLASSIFICATION = Object.freeze([
  {
    key: STORAGE_KEYS.IDENTITY,
    class: STORAGE_CLASS.AUTHORITATIVE_LOCAL,
    scope: 'global',
    description:
      'Ed25519 transport seed (NodeId/operator key); one browser install == one identity. Mnemonic-derived on new installs; a legacy random seed is preserved, never silently rekeyed.',
  },
  {
    key: STORAGE_KEYS.USER_IDENTITY,
    class: STORAGE_CLASS.AUTHORITATIVE_LOCAL,
    scope: 'global',
    description:
      'R3 user identity record (EIP-55 address + the derived secp256k1 secret, passkey-enrolled flag, provenance). The mnemonic itself is never stored; the derived secret is persisted so a reload signs without an unlock.',
  },
  {
    key: 'pinned_ledger',
    class: STORAGE_CLASS.AUTHORITATIVE_LOCAL,
    scope: 'blob-field',
    storage: STORAGE_KEYS.LEDGER,
    description: 'TOFU anchor: the routing leaf ledger key a receipt must verify under.',
  },
  {
    key: 'pinned_leaf_keys',
    class: STORAGE_CLASS.AUTHORITATIVE_LOCAL,
    scope: 'blob-field',
    storage: STORAGE_KEYS.LEDGER,
    description: 'TOFU/out-of-band anchors: payee leaf ledger keys a terminal proof must verify under.',
  },
  {
    key: STORAGE_KEYS.STATE,
    class: STORAGE_CLASS.BEST_EFFORT_CACHE,
    scope: 'identity',
    description: 'Client/local-state blob (outbound join, rejection). Re-derivable; absence tolerated.',
  },
  {
    key: STORAGE_KEYS.LEDGER,
    class: STORAGE_CLASS.BEST_EFFORT_CACHE,
    scope: 'identity',
    description: 'Secret-free ledger blob (pins, balance, activity, pending orders). Absence tolerated.',
  },
  {
    key: STORAGE_KEYS.RECOVERY,
    class: STORAGE_CLASS.NON_AUTHORITATIVE_LOCAL,
    scope: 'global',
    description: 'Passive parent-liveness tracker. Informational only.',
  },
  {
    key: STORAGE_KEYS.ADMIN_POLICY,
    class: STORAGE_CLASS.NON_AUTHORITATIVE_LOCAL,
    scope: 'global',
    description: 'Acknowledged admin-policy document hash.',
  },
  {
    key: STORAGE_KEYS.VALUE_PENDING,
    class: STORAGE_CLASS.NON_AUTHORITATIVE_LOCAL,
    scope: 'global',
    description: 'In-flight value-op write journal (idempotency retry key).',
  },
]);

/**
 * Classify a concrete localStorage key (including identity-scoped forms).
 *
 * @param {string} key
 * @returns {string|null} one of `STORAGE_CLASS.*`, or null for an unknown key.
 */
export function classifyStorageKey(key) {
  if (typeof key !== 'string' || key.length === 0) return null;

  // Exact global keys (the identity key includes a `.v1` suffix, so there is no
  // scoped variant to confuse it with).
  for (const row of STORAGE_CLASSIFICATION) {
    if (row.scope === 'blob-field') continue;
    if (row.scope === 'global' && row.key === key) return row.class;
  }

  // Identity-scoped cache keys: `cawala.state.v1:<nodeId>` / `cawala.ledger.v1:<nodeId>`.
  if (key === STORAGE_KEYS.STATE || key.startsWith(`${STORAGE_KEYS.STATE}:`)) {
    return STORAGE_CLASS.BEST_EFFORT_CACHE;
  }
  if (key === STORAGE_KEYS.LEDGER || key.startsWith(`${STORAGE_KEYS.LEDGER}:`)) {
    return STORAGE_CLASS.BEST_EFFORT_CACHE;
  }

  return null;
}

/** Resolve a localStorage-like object, or null when it is unavailable. */
function _resolveStore(store) {
  if (store) return store;
  try {
    if (typeof window !== 'undefined' && window.localStorage) return window.localStorage;
  } catch {
    /* private mode / quota */
  }
  try {
    if (typeof globalThis !== 'undefined' && globalThis.localStorage) {
      return globalThis.localStorage;
    }
  } catch {
    /* ignore */
  }
  return null;
}

/** Decode standard base64 to bytes. Throws on malformed input (caller catches). */
function _base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Read and decode an identity-scoped base64 blob, falling back once to the
 * legacy un-namespaced key. Best-effort: returns null (never throws) for a
 * missing, unreadable, or malformed blob.
 *
 * @param {string} base The un-suffixed key, e.g. `cawala.state.v1`.
 * @param {string} nodeId
 * @param {{ store?: any, onWarn?: (kind: 'read'|'decode', err: unknown) => void }} [options]
 * @returns {Uint8Array|null}
 */
export function readScopedBlob(base, nodeId, options = {}) {
  const store = _resolveStore(options.store);
  if (!store) {
    options.onWarn?.('read', new Error('storage unavailable'));
    return null;
  }

  let b64 = null;
  try {
    b64 = store.getItem(`${base}:${nodeId}`);
    if (b64 == null) {
      // One-time backward compat: pre-portability installs stored the blob
      // under the un-suffixed key.
      b64 = store.getItem(base);
    }
  } catch (err) {
    options.onWarn?.('read', err);
    return null;
  }
  if (!b64) return null;

  try {
    return _base64ToBytes(b64);
  } catch (err) {
    options.onWarn?.('decode', err);
    return null;
  }
}

/**
 * Import the persisted state/ledger blobs into a live node, tolerating a
 * missing or corrupt blob. Boot must proceed with empty local state rather than
 * throw: balance/height are re-validated from the node afterwards.
 *
 * @param {object|null} node A wasm `ClientNode` (or a test double).
 * @param {{ stateBytes?: Uint8Array|null, ledgerBytes?: Uint8Array|null, onWarn?: (kind: string, err: unknown) => void }} [input]
 * @returns {{ stateImported: boolean, ledgerImported: boolean }}
 */
export function restoreBlobs(node, input = {}) {
  const result = { stateImported: false, ledgerImported: false };
  if (!node) return result;

  const attempts = [
    ['state', input.stateBytes, 'import_state', 'stateImported'],
    ['ledger', input.ledgerBytes, 'import_ledger_state', 'ledgerImported'],
  ];

  for (const [kind, bytes, method, flag] of attempts) {
    if (!bytes || bytes.length === 0) continue;
    if (typeof node[method] !== 'function') continue;
    try {
      node[method](bytes);
      result[flag] = true;
    } catch (err) {
      // A corrupt blob must not block boot: start from a fresh local state.
      input.onWarn?.(kind, err);
    }
  }

  return result;
}
