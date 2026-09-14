import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  IDENTITY_BUNDLE_VERSION,
  PBKDF2_ITERATIONS,
  encryptIdentityBundle,
  decryptIdentityBundle,
  inspectIdentityBundle,
  parseIdentityBundle,
  serializeIdentityBundle,
} from '../src/lib/identityBundle.js';

const SEED_HEX = 'a1'.repeat(32); // 64 hex chars
const NODE_ID = 'b2'.repeat(32); // 64 hex chars
const PASSPHRASE = 'correct horse battery staple';

function makeStateB64() {
  return Buffer.from('postcard-state-bytes').toString('base64');
}

function makeLedgerB64() {
  return Buffer.from('ledger-state-bytes').toString('base64');
}

async function makeBundle(overrides = {}) {
  return encryptIdentityBundle({
    seedHex: SEED_HEX,
    stateB64: makeStateB64(),
    ledgerB64: makeLedgerB64(),
    nodeId: NODE_ID,
    passphrase: PASSPHRASE,
    ...overrides,
  });
}

test('round-trip returns identical seed/state/ledger and nodeId', async () => {
  const bundle = await makeBundle();
  const out = await decryptIdentityBundle(bundle, PASSPHRASE);

  assert.equal(out.version, IDENTITY_BUNDLE_VERSION);
  assert.equal(out.nodeId, NODE_ID);
  assert.equal(out.seedHex, SEED_HEX);
  assert.equal(out.stateB64, makeStateB64());
  assert.equal(out.ledgerB64, makeLedgerB64());
});

test('round-trip supports null state/ledger', async () => {
  const bundle = await makeBundle({ stateB64: null, ledgerB64: null });
  const out = await decryptIdentityBundle(bundle, PASSPHRASE);
  assert.equal(out.stateB64, null);
  assert.equal(out.ledgerB64, null);
});

test('wrong passphrase rejects with the friendly error', async () => {
  const bundle = await makeBundle();
  await assert.rejects(
    () => decryptIdentityBundle(bundle, 'not the passphrase'),
    /Incorrect passphrase or corrupted bundle/,
  );
});

test('tampered ciphertext rejects', async () => {
  const bundle = await makeBundle();
  const raw = Buffer.from(bundle.ct, 'base64');
  raw[raw.length - 1] ^= 0xff; // flip a byte in the GCM tag
  const tampered = { ...bundle, ct: raw.toString('base64') };

  await assert.rejects(
    () => decryptIdentityBundle(tampered, PASSPHRASE),
    /Incorrect passphrase or corrupted bundle/,
  );
});

test('tampered cleartext nodeId (AAD mismatch) rejects', async () => {
  const bundle = await makeBundle();
  const tampered = { ...bundle, nodeId: 'c3'.repeat(32) };

  await assert.rejects(
    () => decryptIdentityBundle(tampered, PASSPHRASE),
    /Incorrect passphrase or corrupted bundle/,
  );
});

test('inspectIdentityBundle returns metadata without a passphrase', async () => {
  const bundle = await makeBundle();
  const meta = inspectIdentityBundle(bundle);

  assert.deepEqual(meta, {
    version: IDENTITY_BUNDLE_VERSION,
    nodeId: NODE_ID,
    kdf: 'PBKDF2-SHA-256',
    aead: 'AES-256-GCM',
  });
  // Never leaks secret material.
  assert.equal(Object.hasOwn(meta, 'ct'), false);
  assert.equal(Object.hasOwn(meta, 'seedHex'), false);
});

test('inspectIdentityBundle rejects unsupported version', async () => {
  const bundle = await makeBundle();
  assert.throws(
    () => inspectIdentityBundle({ ...bundle, v: 2 }),
    /Unsupported identity bundle version/,
  );
});

test('inspectIdentityBundle rejects malformed structure', () => {
  assert.throws(() => inspectIdentityBundle(null), /Malformed identity bundle/);
  assert.throws(() => inspectIdentityBundle({}), /Malformed identity bundle/);
  assert.throws(
    () => inspectIdentityBundle({ v: 1, nodeId: 'short' }),
    /Malformed identity bundle/,
  );
});

test('empty passphrase is rejected', async () => {
  const bundle = await makeBundle();
  await assert.rejects(() => decryptIdentityBundle(bundle, ''), /Passphrase is required/);
  await assert.rejects(
    () => encryptIdentityBundle({ seedHex: SEED_HEX, nodeId: NODE_ID, passphrase: '' }),
    /Passphrase is required/,
  );
});

test('leak guard: serialized bundle never contains the seed', async () => {
  const bundle = await makeBundle();
  const serialized = serializeIdentityBundle(bundle);

  assert.equal(serialized.includes(SEED_HEX), false);
  assert.equal(serialized.toLowerCase().includes(SEED_HEX), false);
  assert.equal(serialized.includes('seedHex'), false);
  // The public metadata is still present.
  assert.equal(serialized.includes(NODE_ID), true);
});

test('parse/serialize round-trip', async () => {
  const bundle = await makeBundle();
  const parsed = parseIdentityBundle(serializeIdentityBundle(bundle));
  assert.deepEqual(parsed, bundle);
  const out = await decryptIdentityBundle(parsed, PASSPHRASE);
  assert.equal(out.seedHex, SEED_HEX);
});

test('parseIdentityBundle rejects malformed JSON with a friendly error', () => {
  assert.throws(() => parseIdentityBundle('{not json'), /Malformed identity bundle/);
  assert.throws(() => parseIdentityBundle(''), /Malformed identity bundle/);
});

test('frozen constants: PBKDF2_ITERATIONS >= 600000 and version 1', async () => {
  assert.equal(IDENTITY_BUNDLE_VERSION, 1);
  assert.ok(PBKDF2_ITERATIONS >= 600000);
  const bundle = await makeBundle();
  assert.equal(bundle.v, 1);
  assert.ok(bundle.kdf.iterations >= 600000);
});
