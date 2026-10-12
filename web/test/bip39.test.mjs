import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * BIP-39 engine tests (identity UI lane).
 *
 * Pins the credential format the identity flows depend on: real wordlist
 * validation, checksum detection, and generation round-trips. The PBKDF2 seed
 * stretch was moved into the wasm engine (and the dead JS helper removed), so
 * it is covered by the wasm/Rust tests, not here.
 */

import {
  VALID_WORD_COUNTS,
  MNEMONIC_ERRORS,
  normalizeMnemonic,
  mnemonicWords,
  validateMnemonic,
  generateMnemonic,
} from '../src/lib/bip39.js';
import { BIP39_WORDLIST, BIP39_WORD_INDEX } from '../src/lib/bip39Wordlist.js';

const GOOD_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

test('wordlist is the canonical 2048 words with stable indices', () => {
  assert.equal(BIP39_WORDLIST.length, 2048);
  assert.equal(BIP39_WORD_INDEX.abandon, 0);
  assert.equal(BIP39_WORD_INDEX.zoo, 2047);
  assert.equal(BIP39_WORDLIST[BIP39_WORD_INDEX.about], 'about');
});

test('normalizeMnemonic trims, lowercases and collapses whitespace', () => {
  assert.equal(normalizeMnemonic('  ABANDON\n\tAbout   '), 'abandon about');
  assert.equal(normalizeMnemonic(''), '');
  assert.equal(normalizeMnemonic(null), '');
  assert.deepEqual(mnemonicWords('zoo\tability'), ['zoo', 'ability']);
});

test('validateMnemonic accepts a known-good 12-word phrase', async () => {
  const result = await validateMnemonic(GOOD_12);
  assert.equal(result.ok, true);
  assert.equal(result.error, null);
  assert.equal(result.words.length, 12);
  assert.equal(result.normalized, GOOD_12);
});

test('validateMnemonic normalizes pasted casing and newlines', async () => {
  const result = await validateMnemonic(`Abandon\nABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon ABOUT`);
  assert.equal(result.ok, true);
  assert.equal(result.normalized, GOOD_12);
});

test('validateMnemonic rejects an empty phrase', async () => {
  const result = await validateMnemonic('   \n ');
  assert.equal(result.ok, false);
  assert.equal(result.error.code, MNEMONIC_ERRORS.EMPTY);
});

test('validateMnemonic rejects the wrong word count', async () => {
  const result = await validateMnemonic('abandon about');
  assert.equal(result.ok, false);
  assert.equal(result.error.code, MNEMONIC_ERRORS.WORD_COUNT);
  assert.match(result.error.message, /12, 15, 18, 21, 24/);
  assert.match(result.error.message, /has 2/);
});

test('validateMnemonic flags the unknown word by position', async () => {
  const phrase = `${'abandon '.repeat(11)}wibble`.trim();
  const result = await validateMnemonic(phrase);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, MNEMONIC_ERRORS.UNKNOWN_WORD);
  assert.equal(result.error.wordIndex, 11);
  assert.match(result.error.message, /Word 12/);
});

test('validateMnemonic rejects a bad checksum even with known words', async () => {
  // 11×abandon must end in "about"; "art" breaks the checksum.
  const phrase = `${'abandon '.repeat(11)}art`.trim();
  const result = await validateMnemonic(phrase);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, MNEMONIC_ERRORS.CHECKSUM);
});

test('generateMnemonic round-trips through validation at every strength', async () => {
  const seen = new Set();
  for (const [strength, expectedWords] of [
    [128, 12],
    [160, 15],
    [192, 18],
    [224, 21],
    [256, 24],
  ]) {
    const mnemonic = await generateMnemonic(strength);
    const words = mnemonic.split(' ');
    assert.equal(words.length, expectedWords, `${strength}-bit word count`);
    assert.ok(!seen.has(mnemonic), 'fresh entropy per call');
    seen.add(mnemonic);
    const result = await validateMnemonic(mnemonic);
    assert.equal(result.ok, true, `${strength}-bit checksum`);
    assert.ok(VALID_WORD_COUNTS.includes(result.words.length));
  }
});

test('generateMnemonic rejects unsupported strength', async () => {
  await assert.rejects(() => generateMnemonic(100), /Unsupported mnemonic strength/);
});
