/**
 * Cawala — admin unlock policy acknowledgement (R6, P4).
 *
 * The policy document (`ADMIN_POLICY.md` at the repo root) is rendered inside
 * the admin unlock dialog, and unlocking only proceeds once the reader ticks an
 * explicit acknowledgement. What is remembered afterwards is the *hash of the
 * document that was acknowledged* (localStorage), so editing the policy
 * invalidates every past acknowledgement and the gate shows the changed
 * document again.
 *
 * The "admin mode is unlocked" flag itself is deliberately **not** stored
 * here: it lives in memory only (`adminLock` in `stores.svelte.js`), so a
 * reload always lands back on the lock gate.
 */

import policyText from '../../../ADMIN_POLICY.md?raw';

/** localStorage key for the acknowledged policy hash. */
export const POLICY_STORAGE_KEY = 'cawala.admin.policy.v1';

/** The raw policy document, rendered by the unlock dialog. */
export const POLICY_TEXT = String(policyText ?? '');

/**
 * FNV-1a over the document, as 8 lowercase hex characters. Synchronous and
 * dependency-free so the gate can compare "document I showed" with "document
 * that was acknowledged" on every load.
 *
 * @param {string} text
 * @returns {string}
 */
export function hashPolicyText(text) {
  let hash = 0x811c9dc5;
  const value = String(text ?? '');
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

/** Hash of the policy document this build ships. */
export const POLICY_HASH = hashPolicyText(POLICY_TEXT);

/** Resolve localStorage, or null when it is unavailable. */
function _store() {
  try {
    if (typeof window !== 'undefined' && window.localStorage) return window.localStorage;
  } catch {
    /* private mode / quota */
  }
  return null;
}

/**
 * The last acknowledged policy, or null when this browser never acknowledged
 * one (or storage is unavailable).
 *
 * @returns {{ hash: string, at: number|null }|null}
 */
export function readAcknowledgedPolicy() {
  const store = _store();
  if (!store) return null;
  try {
    const raw = store.getItem(POLICY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.hash === 'string' && parsed.hash) {
      return { hash: parsed.hash, at: typeof parsed.at === 'number' ? parsed.at : null };
    }
  } catch {
    /* corrupt entry: treat as never acknowledged */
  }
  return null;
}

/**
 * Record an acknowledgement of `hash` (defaults to the shipped document).
 * Best-effort: returns false when storage is unavailable.
 *
 * @param {string} [hash]
 * @returns {boolean}
 */
export function writeAcknowledgedPolicy(hash = POLICY_HASH) {
  const store = _store();
  if (!store) return false;
  try {
    store.setItem(POLICY_STORAGE_KEY, JSON.stringify({ hash, at: Date.now() }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether the stored acknowledgement belongs to the shipped document.
 * An edit to `ADMIN_POLICY.md` makes this false, which is what invalidates it.
 *
 * @returns {boolean}
 */
export function policyAcknowledgementCurrent() {
  const stored = readAcknowledgedPolicy();
  return Boolean(stored && stored.hash === POLICY_HASH);
}
