/**
 * Cawala M4 — API adapter (single boundary between UI and WASM/control layer).
 *
 * ALL calls to the wasm client and control message layer go through this module.
 * Components never import from ../wasm/ directly.
 *
 * Mock mode:
 *   - By default (or when `?mock` is in the URL, or when wasm init fails),
 *     every function returns plausible fake data so the UI can be developed
 *     and reviewed without a live node.
 *   - To swap in real wasm: call `initRealClient()` which loads the wasm
 *     module and sets a module-level flag. All functions check that flag
 *     and branch accordingly.
 *
 * TODO(control): When the Rust control message surface is finalized,
 *   replace the mock branches with real `send_envelope` / `try_recv_envelope`
 *   calls that encode/decode control payloads. The function signatures below
 *   are the contract — changing them should require touching only this file.
 */

import {
  CLIENT_STATUS,
  CONNECTION,
  ACTIVITY_TYPES,
} from './constants.js';

// ── Internal state ────────────────────────────────────────────

let _useMock = true;
let _wasmModule = null;
let _clientNode = null;

/**
 * Whether we are running in mock mode.
 */
export function isMockMode() {
  return _useMock;
}

// ── Initialization ────────────────────────────────────────────

/**
 * Initialize the API layer.
 * In mock mode this is a no-op. In real mode it loads the wasm module.
 *
 * TODO(control): Wire up real wasm init here.
 */
export async function initApi() {
  // Check URL param for forced mock
  const params = new URLSearchParams(window.location.search);
  if (params.has('mock')) {
    _useMock = true;
    return;
  }

  // TODO(control): Try to load the real wasm module.
  // For now, always use mock mode.
  try {
    // const init = (await import('../wasm/cawala_client.js')).default;
    // await init();
    // _wasmModule = await import('../wasm/cawala_client.js');
    // _useMock = false;
    _useMock = true;
  } catch {
    console.warn('[api] wasm init failed, using mock data');
    _useMock = true;
  }
}

// ── Client lifecycle ──────────────────────────────────────────

/**
 * Spawn a client node (or mock equivalent).
 * @returns {Promise<{ endpointId: string, address: string|null }>}
 */
export async function spawnClient() {
  if (_useMock) {
    await mockDelay(300);
    return {
      endpointId: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      address: '0.3.1',
    };
  }
  // TODO(control): real wasm spawn
  throw new Error('Not implemented: real spawnClient');
}

/**
 * Spawn a client with a known address (for join flow).
 * @param {string} address
 * @returns {Promise<{ endpointId: string, address: string }>}
 */
export async function spawnClientWithAddress(address) {
  if (_useMock) {
    await mockDelay(300);
    return {
      endpointId: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      address,
    };
  }
  // TODO(control): real wasm spawn_with_address
  throw new Error('Not implemented: real spawnClientWithAddress');
}

/**
 * Destroy the current client.
 */
export function destroyClient() {
  _clientNode = null;
  // TODO(control): real wasm free
}

// ── Identity & connection ─────────────────────────────────────

/**
 * Get the current endpoint ID.
 * @returns {string}
 */
export function getEndpointId() {
  if (_useMock) return 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  // TODO(control): return _clientNode.endpoint_id()
  return '';
}

/**
 * Get the current messaging address.
 * @returns {string|null}
 */
export function getAddress() {
  if (_useMock) return '0.3.1';
  // TODO(control): return _clientNode.address()
  return null;
}

/**
 * Get connection status.
 * @returns {string} One of CONNECTION.*
 */
export function getConnectionStatus() {
  if (_useMock) return CONNECTION.CONNECTED;
  // TODO(control): real status
  return CONNECTION.DISCONNECTED;
}

// ── Ping (existing wasm surface) ──────────────────────────────

/**
 * Send a ping to another endpoint.
 * @param {string} targetEndpointId
 * @param {string} payload
 * @returns {Promise<string>} Pong payload.
 */
export async function ping(targetEndpointId, payload) {
  if (_useMock) {
    await mockDelay(200);
    return payload;
  }
  // TODO(control): real wasm ping
  throw new Error('Not implemented: real ping');
}

// ── Messaging (existing wasm surface) ─────────────────────────

/**
 * Send an envelope to the network.
 * @param {string} nextHop - Endpoint ID of the direct neighbor.
 * @param {string} dst - Final destination address.
 * @param {number} msgType - Message type discriminator.
 * @param {Uint8Array} payload - Raw payload bytes.
 * @returns {Promise<string>} Ack status string.
 */
export async function sendEnvelope(nextHop, dst, msgType, payload) {
  if (_useMock) {
    await mockDelay(150);
    return 'delivered';
  }
  // TODO(control): real wasm send_envelope
  throw new Error('Not implemented: real sendEnvelope');
}

/**
 * Try to receive the next envelope (non-blocking).
 * @returns {object|null} ReceivedEnvelope or null if queue empty.
 */
export function tryRecvEnvelope() {
  if (_useMock) return null;
  // TODO(control): real wasm try_recv_envelope
  return null;
}

// ── Control messages (TODO(control): real implementations) ─────

/**
 * Request to join a parent node.
 * @param {string} parentEndpointId
 * @param {string|null} addressHint
 * @returns {Promise<{ status: string, address?: string }>}
 */
export async function requestJoin(parentEndpointId, addressHint) {
  if (_useMock) {
    await mockDelay(600);
    return { status: 'pending' };
  }
  // TODO(control): encode JOIN_REQUEST envelope, send, await ack
  throw new Error('Not implemented: real requestJoin');
}

/**
 * Approve a pending join request.
 * @param {string} childEndpointId
 * @param {number|null} slot
 * @returns {Promise<{ status: string, address: string }>}
 */
export async function approveJoin(childEndpointId, slot) {
  if (_useMock) {
    await mockDelay(400);
    const s = slot ?? 4;
    return { status: 'approved', address: `0.3.${s}` };
  }
  // TODO(control): encode JOIN_APPROVED envelope
  throw new Error('Not implemented: real approveJoin');
}

/**
 * Reject a pending join request.
 * @param {string} childEndpointId
 * @returns {Promise<{ status: string }>}
 */
export async function rejectJoin(childEndpointId) {
  if (_useMock) {
    await mockDelay(300);
    return { status: 'rejected' };
  }
  // TODO(control): encode JOIN_REJECTED envelope
  throw new Error('Not implemented: real rejectJoin');
}

/**
 * Create a new child node.
 * @param {number|null} slot
 * @returns {Promise<{ status: string, address: string }>}
 */
export async function createChild(slot) {
  if (_useMock) {
    await mockDelay(500);
    const s = slot ?? 5;
    return { status: 'created', address: `0.3.${s}` };
  }
  // TODO(control): encode TOPO_CREATE_CHILD envelope
  throw new Error('Not implemented: real createChild');
}

/**
 * Move a child to a new slot/parent.
 * @param {string} childAddress
 * @param {string} newParentAddress
 * @param {number} newSlot
 * @returns {Promise<{ status: string, newAddress: string }>}
 */
export async function moveChild(childAddress, newParentAddress, newSlot) {
  if (_useMock) {
    await mockDelay(500);
    return { status: 'moved', newAddress: `${newParentAddress}.${newSlot}` };
  }
  // TODO(control): encode TOPO_MOVE_CHILD envelope
  throw new Error('Not implemented: real moveChild');
}

/**
 * Detach a child.
 * @param {string} childAddress
 * @returns {Promise<{ status: string }>}
 */
export async function detachChild(childAddress) {
  if (_useMock) {
    await mockDelay(400);
    return { status: 'detached' };
  }
  // TODO(control): encode TOPO_DETACH_CHILD envelope
  throw new Error('Not implemented: real detachChild');
}

/**
 * Issue or burn value against an account.
 * @param {string} accountAddress
 * @param {number} amount - Positive = issue, negative = burn.
 * @param {string} reason
 * @returns {Promise<{ status: string, newBalance: number }>}
 */
export async function issueBurn(accountAddress, amount, reason) {
  if (_useMock) {
    await mockDelay(400);
    // Find the mock account and adjust
    const acct = MOCK_DATA.accounts.find((a) => a.address === accountAddress);
    const newBalance = (acct ? acct.balance : 0) + amount;
    return { status: amount > 0 ? 'issued' : 'burned', newBalance };
  }
  // TODO(control): encode LEDGER_ADJUST envelope
  throw new Error('Not implemented: real issueBurn');
}

// ── Invite parsing ────────────────────────────────────────────

/**
 * Parse and validate a Cawala invite code/URI.
 *
 * Accepted formats:
 *   - Full URI: cawala://join?parent=<EndpointId>&op=<64-hex>&slot=<0..7>&exp=<unix>&label=<encoded>
 *   - Bare base64url: a URL-safe base64 string (no prefix) — decoded as JSON
 *     with the same fields.
 *
 * @param {string} code - Raw invite string from the user.
 * @returns {Promise<{ parent: string, operator: string, slot?: number, expiry?: number, label?: string }>}
 * @throws {Error} With a user-facing message if the invite is invalid.
 */
export async function parseInvite(code) {
  const trimmed = (code || '').trim();
  if (!trimmed) {
    throw new Error('Paste an invite code or link from a node operator.');
  }

  if (_useMock) {
    await mockDelay(150);
    return _mockParseInvite(trimmed);
  }

  // TODO(wasm): Decode the invite using the Rust invite format.
  // The Rust side will expose a parse_invite() function that returns
  // the structured fields. For now, mirror the URI parsing logic so
  // the UI is ready when the wasm surface lands.
  throw new Error('Not implemented: real parseInvite');
}

/**
 * Mock invite parser. Recognises:
 *   - cawala://join?parent=...&op=... (valid)
 *   - Anything else that looks vaguely like base64 (valid with defaults)
 *   - Empty / garbage → throws
 */
function _mockParseInvite(raw) {
  // Try URI format first
  try {
    const url = new URL(raw);
    if (url.protocol === 'cawala:' && url.pathname === '/join') {
      const parent = url.searchParams.get('parent');
      const op = url.searchParams.get('op');
      if (!parent || !op) {
        throw new Error('Invite is missing required fields (parent, operator key).');
      }
      if (!/^[0-9a-fA-F]{64}$/.test(op)) {
        throw new Error('Operator key must be 64 hex characters.');
      }
      const slotRaw = url.searchParams.get('slot');
      const expRaw = url.searchParams.get('exp');
      const labelRaw = url.searchParams.get('label');
      const result = {
        parent,
        operator: op,
      };
      if (slotRaw != null) {
        const slot = Number(slotRaw);
        if (!Number.isInteger(slot) || slot < 0 || slot > 7) {
          throw new Error('Slot must be an integer between 0 and 7.');
        }
        result.slot = slot;
      }
      if (expRaw != null) {
        const exp = Number(expRaw);
        if (!Number.isFinite(exp) || exp <= 0) {
          throw new Error('Expiry must be a valid unix timestamp.');
        }
        result.expiry = exp;
      }
      if (labelRaw) {
        result.label = decodeURIComponent(labelRaw);
      }
      return result;
    }
  } catch (e) {
    // If it was a URL parse error or a validation error we threw, re-throw validation errors
    if (e.message && !e.message.includes('Invalid URL')) {
      throw e;
    }
  }

  // Try bare base64url JSON
  try {
    const padded = raw.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(padded);
    const obj = JSON.parse(json);
    if (obj.parent && obj.op) {
      const result = { parent: obj.parent, operator: obj.op };
      if (obj.slot != null) result.slot = obj.slot;
      if (obj.exp != null) result.expiry = obj.exp;
      if (obj.label) result.label = obj.label;
      return result;
    }
    throw new Error('Invite is missing required fields (parent, operator key).');
  } catch (e) {
    if (e.message && e.message.includes('missing required')) {
      throw e;
    }
  }

  // Nothing worked
  throw new Error("That doesn't look like a cawala invite. Ask the node operator to send a fresh one.");
}

// ── Data fetching ─────────────────────────────────────────────

/**
 * Get the list of children for this node.
 * @returns {Promise<Array>}
 */
export async function getChildren() {
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.children];
  }
  // TODO(control): request via control messages
  throw new Error('Not implemented: real getChildren');
}

/**
 * Get accounts held by this node.
 * @returns {Promise<Array>}
 */
export async function getAccounts() {
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.accounts];
  }
  // TODO(control): request via control messages
  throw new Error('Not implemented: real getAccounts');
}

/**
 * Get pending join requests.
 * @returns {Promise<Array>}
 */
export async function getJoinRequests() {
  if (_useMock) {
    await mockDelay(200);
    return [...MOCK_DATA.joinRequests];
  }
  // TODO(control): request via control messages
  throw new Error('Not implemented: real getJoinRequests');
}

/**
 * Get activity log entries.
 * @param {object} [filters]
 * @param {string} [filters.type]
 * @param {string} [filters.address]
 * @returns {Promise<Array>}
 */
export async function getActivityLog(filters) {
  if (_useMock) {
    await mockDelay(200);
    let entries = [...MOCK_DATA.activity];
    if (filters?.type) {
      entries = entries.filter((e) => e.type === filters.type);
    }
    if (filters?.address) {
      const addr = filters.address.toLowerCase();
      entries = entries.filter(
        (e) =>
          (e.from && e.from.toLowerCase().includes(addr)) ||
          (e.to && e.to.toLowerCase().includes(addr)),
      );
    }
    return entries;
  }
  // TODO(control): request via control messages
  throw new Error('Not implemented: real getActivityLog');
}

/**
 * Look up a suggested address by location.
 * @param {number} lat
 * @param {number} lon
 * @returns {Promise<string|null>}
 */
export async function lookupAddressByLocation(lat, lon) {
  if (_useMock) {
    await mockDelay(400);
    // Mock: return a plausible address based on rough region
    return '0.3';
  }
  // TODO(control): query location SQLite service
  throw new Error('Not implemented: real lookupAddressByLocation');
}

// ── Mock data ─────────────────────────────────────────────────

const MOCK_DATA = {
  children: [
    {
      address: '0.3.1',
      endpointId: 'z6MkHs7Kj3xVnR5pQw9bYf2dLg8mC4tEa6uIiOoPp',
      balance: 1200,
      seniority: '2025-01-15T00:00:00Z',
      online: true,
      slot: 1,
    },
    {
      address: '0.3.2',
      endpointId: 'z6MkRt5nYh7kJf3gWp2xDs9cVq6bLm4eAf8uOiIiPpOo',
      balance: 800,
      seniority: '2025-03-22T00:00:00Z',
      online: false,
      slot: 2,
    },
    {
      address: '0.3.3',
      endpointId: 'z6MkBu4iNk8mHj2fXs7cWr5eVq3dLp9gAj6uOiIiPpOo',
      balance: 2100,
      seniority: '2024-11-08T00:00:00Z',
      online: true,
      slot: 3,
    },
  ],
  accounts: [
    // Liability accounts (held for children)
    {
      address: '0.3.1',
      type: 'liability',
      label: 'Account for 0.3.1',
      balance: 1200,
    },
    {
      address: '0.3.2',
      type: 'liability',
      label: 'Account for 0.3.2',
      balance: 800,
    },
    {
      address: '0.3.3',
      type: 'liability',
      label: 'Account for 0.3.3',
      balance: 2100,
    },
    // Asset account (with parent)
    {
      address: '0.3',
      type: 'asset',
      label: 'Account with parent 0.3',
      balance: 4500,
    },
    // Equity
    {
      address: '0.3',
      type: 'equity',
      label: 'Node equity',
      balance: 400,
    },
  ],
  joinRequests: [
    {
      endpointId: 'z6MkPq8rSt2nWk5jHf9cXm3dLg7bVq4eAf6uOiIiPpOo',
      requestedAddress: null,
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      status: 'pending',
    },
    {
      endpointId: 'z6MkDf6gHj3kLm8nBc4vXs2rWq5eTy9iAp7uOiIiPpOo',
      requestedAddress: '0.3.7',
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      status: 'pending',
    },
  ],
  activity: [
    {
      id: 'a1',
      type: ACTIVITY_TYPES.TRANSFER,
      from: '0.3.1',
      to: '0.3.2',
      amount: 150,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 1800000).toISOString(),
    },
    {
      id: 'a2',
      type: ACTIVITY_TYPES.ISSUE,
      from: null,
      to: '0.3.1',
      amount: 500,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 86400000).toISOString(),
    },
    {
      id: 'a3',
      type: ACTIVITY_TYPES.JOIN_APPROVED,
      from: null,
      to: '0.3.3',
      amount: null,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 172800000).toISOString(),
    },
    {
      id: 'a4',
      type: ACTIVITY_TYPES.TOPO_CREATE,
      from: null,
      to: '0.3.2',
      amount: null,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 259200000).toISOString(),
    },
    {
      id: 'a5',
      type: ACTIVITY_TYPES.TRANSFER,
      from: '0.3.3',
      to: '0.3.1',
      amount: 300,
      signedBy: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      timestamp: new Date(Date.now() - 345600000).toISOString(),
    },
  ],
};

// ── Mock helpers ──────────────────────────────────────────────

/**
 * Simulate network delay.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function mockDelay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
