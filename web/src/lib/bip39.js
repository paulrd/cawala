/**
 * Cawala — BIP-39 mnemonic handling (client-side, dependency-free).
 *
 * Real BIP-39 English: entropy generation and checksum validation. This is the
 * standard credential the user writes down; the wasm crypto engine owns key
 * *derivation* from the seed (BIP-32 path m/44'/60'/0'/0/0, secp256k1, keccak)
 * — see `.slim/deepwork/portable-client-refactor-spec.md` §1.1. The
 * PBKDF2-SHA-512 seed stretch also lives in wasm (the JS `mnemonicToSeedHex`
 * helper was removed as dead once the engine landed).
 *
 * Pure ESM, no DOM, no dependencies — works in browsers and Node (used by
 * `node --test` directly). Checksum validation is async because WebCrypto
 * `digest()` is.
 */

import { BIP39_WORDLIST, BIP39_WORD_INDEX } from './bip39Wordlist.js';

/** Accepted word counts (12/15/18/21/24 words == 128..256 bits of entropy). */
export const VALID_WORD_COUNTS = Object.freeze([12, 15, 18, 21, 24]);

/** Stable machine-readable validation error codes. */
export const MNEMONIC_ERRORS = Object.freeze({
  EMPTY: 'empty',
  WORD_COUNT: 'word_count',
  UNKNOWN_WORD: 'unknown_word',
  CHECKSUM: 'checksum',
});

/**
 * Normalize free-typed text into a candidate mnemonic: trim, lowercase,
 * collapse every run of whitespace to a single space. Accepts pasted phrases
 * with newlines or extra spaces.
 *
 * @param {string} text
 * @returns {string}
 */
export function normalizeMnemonic(text) {
  if (typeof text !== 'string') return '';
  return text.trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Split normalized text into words.
 * @param {string} text
 * @returns {string[]}
 */
export function mnemonicWords(text) {
  const normalized = normalizeMnemonic(text);
  return normalized === '' ? [] : normalized.split(' ');
}

/**
 * Validate a mnemonic against the BIP-39 English wordlist and checksum.
 * Never throws; returns a structured result so the UI can map every failure
 * to a specific, fixable message. Async because the checksum needs
 * WebCrypto SHA-256.
 *
 * @param {string} text Free-typed phrase (normalized first).
 * @returns {Promise<{ ok: boolean, words: string[], normalized: string, error: { code: string, message: string, wordIndex?: number }|null }>}
 */
export async function validateMnemonic(text) {
  const normalized = normalizeMnemonic(text);
  const words = mnemonicWords(text);
  const fail = (code, message, wordIndex) => ({
    ok: false,
    words,
    normalized,
    error: wordIndex == null ? { code, message } : { code, message, wordIndex },
  });

  if (words.length === 0) {
    return fail(MNEMONIC_ERRORS.EMPTY, 'Enter your recovery phrase.');
  }
  if (!VALID_WORD_COUNTS.includes(words.length)) {
    return fail(
      MNEMONIC_ERRORS.WORD_COUNT,
      `A recovery phrase has ${VALID_WORD_COUNTS.join(', ')} words. This one has ${words.length}.`,
    );
  }
  for (let i = 0; i < words.length; i++) {
    if (!Object.prototype.hasOwnProperty.call(BIP39_WORD_INDEX, words[i])) {
      return fail(
        MNEMONIC_ERRORS.UNKNOWN_WORD,
        `Word ${i + 1} (“${words[i]}”) isn’t in the standard word list. Check the spelling — every word is lowercase and there are no numbers.`,
        i,
      );
    }
  }

  // Checksum: ENT/32 checksum bits trail the entropy in the 11-bit word stream.
  const bits = _wordsToBits(words);
  const checksumLength = bits.length / 33;
  const entropyBits = bits.length - checksumLength;
  const entropy = _bitsToBytes(bits.slice(0, entropyBits));
  const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', entropy));
  for (let i = 0; i < checksumLength; i++) {
    const hashBit = (hash[i >> 3] >> (7 - (i & 7))) & 1;
    if (hashBit !== bits[entropyBits + i]) {
      return fail(
        MNEMONIC_ERRORS.CHECKSUM,
        'That phrase doesn’t check out — one or more words are wrong or out of order. A correctly written phrase always passes this check.',
      );
    }
  }

  return { ok: true, words, normalized, error: null };
}

/**
 * Generate a fresh BIP-39 mnemonic.
 *
 * @param {number} [strengthBits=128] Entropy bits: 128 → 12 words (default),
 *   160 → 15, 192 → 18, 224 → 21, 256 → 24.
 * @returns {Promise<string>} Space-joined words.
 * @throws {Error} On unsupported strength.
 */
export async function generateMnemonic(strengthBits = 128) {
  const entropyBytes = strengthBits / 8;
  // words = (ENT + ENT/32 checksum bits) / 11 bits-per-word.
  const wordCount = (strengthBits + strengthBits / 32) / 11;
  if (!VALID_WORD_COUNTS.includes(wordCount)) {
    throw new Error(`Unsupported mnemonic strength: ${strengthBits} bits`);
  }
  const entropy = new Uint8Array(entropyBytes);
  globalThis.crypto.getRandomValues(entropy);

  const checksumBits = entropyBytes / 4; // ENT/32
  const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', entropy));
  const bits = [];
  for (const byte of entropy) {
    for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
  }
  for (let i = 0; i < checksumBits; i++) {
    bits.push((hash[i >> 3] >> (7 - (i & 7))) & 1);
  }

  const words = [];
  for (let w = 0; w < wordCount; w++) {
    let index = 0;
    for (let b = 0; b < 11; b++) index = (index << 1) | bits[w * 11 + b];
    words.push(BIP39_WORDLIST[index]);
  }
  return words.join(' ');
}

// ── Internals ─────────────────────────────────────────────────

/**
 * 11 bits per word, as an array of 0/1.
 * @param {string[]} words
 * @returns {number[]}
 */
function _wordsToBits(words) {
  const bits = [];
  for (const word of words) {
    const index = BIP39_WORD_INDEX[word];
    for (let b = 10; b >= 0; b--) bits.push((index >> b) & 1);
  }
  return bits;
}

/**
 * @param {number[]} bits
 * @returns {Uint8Array}
 */
function _bitsToBytes(bits) {
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) out[i >> 3] |= 1 << (7 - (i & 7));
  }
  return out;
}
