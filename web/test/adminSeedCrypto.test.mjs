import { test } from 'node:test';
import assert from 'node:assert/strict';

const { wrapSeed, unwrapSeed, isWrappedSeed } = await import('../src/lib/adminSeedCrypto.js');

const NODE_A = 'a1'.repeat(32);
const NODE_B = 'b2'.repeat(32);
const SEED = 'c3'.repeat(32);

test('wrap/unwrap round-trips the seed', async () => {
  const wrapped = await wrapSeed(SEED, 'correct horse battery', NODE_A);
  assert.equal(isWrappedSeed(wrapped), true);
  assert.equal(await unwrapSeed(wrapped, 'correct horse battery', NODE_A), SEED);
});

test('a wrong passphrase is rejected', async () => {
  const wrapped = await wrapSeed(SEED, 'right passphrase', NODE_A);
  await assert.rejects(
    () => unwrapSeed(wrapped, 'wrong passphrase', NODE_A),
    /Incorrect passphrase or corrupted/,
  );
});

test('the node id is bound as AAD', async () => {
  const wrapped = await wrapSeed(SEED, 'passphrase', NODE_A);
  await assert.rejects(
    () => unwrapSeed(wrapped, 'passphrase', NODE_B),
    /Incorrect passphrase or corrupted/,
  );
});

test('the wrapped record contains no plaintext seed', async () => {
  const wrapped = await wrapSeed(SEED, 'passphrase', NODE_A);
  const serialized = JSON.stringify(wrapped);
  assert.equal(serialized.includes(SEED), false);
  assert.equal(serialized.includes('seedHex'), false);
  // Only the allowed metadata keys are present.
  assert.deepEqual(Object.keys(wrapped).sort(), ['aead', 'ct', 'kdf']);
});

test('a tampered ciphertext is rejected', async () => {
  const wrapped = await wrapSeed(SEED, 'passphrase', NODE_A);
  const tampered = { ...wrapped, ct: `${wrapped.ct.slice(0, -2)}AA` };
  await assert.rejects(() => unwrapSeed(tampered, 'passphrase', NODE_A));
});

test('each wrap uses a fresh salt and IV', async () => {
  const first = await wrapSeed(SEED, 'passphrase', NODE_A);
  const second = await wrapSeed(SEED, 'passphrase', NODE_A);
  assert.notEqual(first.kdf.salt, second.kdf.salt);
  assert.notEqual(first.aead.iv, second.aead.iv);
  assert.notEqual(first.ct, second.ct);
});

test('a tampered iteration count is rejected (bounded KDF)', async () => {
  const wrapped = await wrapSeed(SEED, 'passphrase', NODE_A);
  const tampered = { ...wrapped, kdf: { ...wrapped.kdf, iterations: 5_000_000_000 } };
  assert.equal(isWrappedSeed(tampered), false);
  await assert.rejects(() => unwrapSeed(tampered, 'passphrase', NODE_A), /Malformed wrapped key/);
});

test('a malformed wrapped record is rejected structurally', async () => {
  assert.equal(isWrappedSeed(null), false);
  assert.equal(isWrappedSeed({}), false);
  assert.equal(isWrappedSeed({ kdf: {}, aead: {}, ct: 'x' }), false);
  await assert.rejects(() => unwrapSeed({ nope: true }, 'p', NODE_A), /Malformed wrapped key/);
});
