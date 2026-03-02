///////////////////////////////////////////////////////////////////////////////
//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          this file is part of the
//        ▄██████████████████████ ▀████▄      leviathan crypto library
//      ▄█████████▀▀▀     ▀███████▄▄███████▌
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  repository
//     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      author: xero (https://x-e.ro)
//       ▀██████   ▄▄██            ▀▀  ██▄    license: mit
//         ▀█████▄   ▄██▄             ▄▀▄▀
//            ▀████▄   ▄██▄                   +---------------+
//              ▐████   ▐███                  |   test spec   |
//       ▄▄██████████    ▐███         ▄▄      +---------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         this file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. the author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// Unit tests for the NESSIE preprocessing helper (test/helpers/nessie.ts)
//
// These tests verify that the byte-reversal transformation is correct in
// isolation BEFORE the full 1284-vector suite runs.
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
  prepareNessieKey,
  prepareNessiePlaintext,
  prepareNessieCiphertext,
  parseNessieVectors,
} from '../helpers/nessie';
import { Serpent } from '../../src/serpent';
import { Convert } from '../../src/base';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function hex(bytes: Uint8Array): string {
  return Convert.bin2hex(bytes).toUpperCase();
}

// ---------------------------------------------------------------------------
// Key preprocessing
// ---------------------------------------------------------------------------

describe('prepareNessieKey', () => {
  it('reverses all 32 bytes of the key', () => {
    // Key with distinct bytes so we can verify reversal:
    const hexKey = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
    const result = prepareNessieKey(hexKey);
    // Reversed: 1F1E...03020100
    const expected = '1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100';
    expect(hex(result)).toBe(expected);
  });

  it('all-zero key remains all-zero after reversal', () => {
    const hexKey = '0'.repeat(64);
    const result = prepareNessieKey(hexKey);
    expect(hex(result)).toBe('0'.repeat(64).toUpperCase());
  });

  it('reversal is its own inverse: applying twice returns the original', () => {
    const hexKey = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
    const once  = prepareNessieKey(hexKey);
    const twice = prepareNessieKey(hex(once));
    expect(hex(twice)).toBe(hexKey.toUpperCase());
  });
});

// ---------------------------------------------------------------------------
// Plaintext preprocessing
// ---------------------------------------------------------------------------

describe('prepareNessiePlaintext', () => {
  it('reverses all 16 bytes of the plaintext', () => {
    const hexPT = '000102030405060708090A0B0C0D0E0F';
    const result = prepareNessiePlaintext(hexPT);
    const expected = '0F0E0D0C0B0A09080706050403020100';
    expect(hex(result)).toBe(expected);
  });

  it('all-zero plaintext remains all-zero', () => {
    const hexPT = '0'.repeat(32);
    const result = prepareNessiePlaintext(hexPT);
    expect(hex(result)).toBe('0'.repeat(32).toUpperCase());
  });

  it('reversal is its own inverse: applying twice returns the original', () => {
    const hexPT = '0123456789ABCDEFFEDCBA9876543210';
    const once  = prepareNessiePlaintext(hexPT);
    const twice = prepareNessiePlaintext(hex(once));
    expect(hex(twice)).toBe(hexPT.toUpperCase());
  });
});

// ---------------------------------------------------------------------------
// Ciphertext preprocessing (same transform as plaintext)
// ---------------------------------------------------------------------------

describe('prepareNessieCiphertext', () => {
  it('applies the same byte-reversal as prepareNessiePlaintext', () => {
    const hexCT = '00112233445566778899AABBCCDDEEFF';
    const ct   = prepareNessieCiphertext(hexCT);
    const pt   = prepareNessiePlaintext(hexCT);
    expect(hex(ct)).toBe(hex(pt));
  });

  it('reversal is its own inverse', () => {
    const hexCT = 'FFEEDDCCBBAA99887766554433221100';
    const once  = prepareNessieCiphertext(hexCT);
    const twice = prepareNessieCiphertext(hex(once));
    expect(hex(twice)).toBe(hexCT.toUpperCase());
  });
});

// ---------------------------------------------------------------------------
// Full known-vector smoke tests
//
// If these fail, do not proceed to 07_nessie_vectors.test.ts.
// ---------------------------------------------------------------------------

describe('Known-vector smoke tests', () => {
  const s = new Serpent();

  // Set 8, vector #0 (non-trivial key AND plaintext)
  it('Set 8, v#0 — encrypt', () => {
    const key   = prepareNessieKey('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    const pt    = prepareNessiePlaintext('3DA46FFA6F4D6F30CD258333E5A61369');
    const expCT = prepareNessieCiphertext('00112233445566778899AABBCCDDEEFF');
    expect(hex(s.encrypt(key, pt))).toBe(hex(expCT));
  });

  it('Set 8, v#0 — decrypt', () => {
    const key   = prepareNessieKey('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    const ct    = prepareNessieCiphertext('00112233445566778899AABBCCDDEEFF');
    const expPT = prepareNessiePlaintext('3DA46FFA6F4D6F30CD258333E5A61369');
    expect(hex(s.decrypt(key, ct))).toBe(hex(expPT));
  });

  // Set 1, v#0 (one-hot key, all-zero PT)
  it('Set 1, v#0 — encrypt', () => {
    const key   = prepareNessieKey('8000000000000000000000000000000000000000000000000000000000000000');
    const pt    = prepareNessiePlaintext('00000000000000000000000000000000');
    const expCT = prepareNessieCiphertext('A223AA1288463C0E2BE38EBD825616C0');
    expect(hex(s.encrypt(key, pt))).toBe(hex(expCT));
  });

  // Set 2, v#0 (all-zero key, one-hot PT)
  it('Set 2, v#0 — encrypt', () => {
    const key   = prepareNessieKey('0000000000000000000000000000000000000000000000000000000000000000');
    const pt    = prepareNessiePlaintext('80000000000000000000000000000000');
    const expCT = prepareNessieCiphertext('8314675E8AD5C3ECD83D852BCF7F566E');
    expect(hex(s.encrypt(key, pt))).toBe(hex(expCT));
  });

  // Set 4, v#0 (key=0001..1F, pt=0011..FF)
  it('Set 4, v#0 — encrypt', () => {
    const key   = prepareNessieKey('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    const pt    = prepareNessiePlaintext('00112233445566778899AABBCCDDEEFF');
    const expCT = prepareNessieCiphertext('2868B7A2D28ECD5E4FDEFAC3C4330074');
    expect(hex(s.encrypt(key, pt))).toBe(hex(expCT));
  });
});

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

describe('parseNessieVectors', () => {
  const VECTORS_DIR = resolve(__dirname, '../vectors');
  const text = readFileSync(
    resolve(VECTORS_DIR, 'Serpent-256-128.verified.test-vectors.txt'),
    'utf8'
  );

  it('parses exactly 1284 vectors', () => {
    const vectors = parseNessieVectors(text);
    expect(vectors.length).toBe(1284);
  });

  it('Set 8, v#0 is parsed with correct fields', () => {
    const vectors = parseNessieVectors(text);
    const v = vectors.find(v => v.set === 'Set 8' && v.num === 0)!;
    expect(v).toBeDefined();
    expect(v.key).toBe('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    expect(v.plain).toBe('3DA46FFA6F4D6F30CD258333E5A61369');
    expect(v.cipher).toBe('00112233445566778899AABBCCDDEEFF');
    expect(v.hasEncryptedField).toBe(true);
  });

  it('Set 3, v#254 (no space before 3-digit number) is parsed correctly', () => {
    const vectors = parseNessieVectors(text);
    const v = vectors.find(v => v.set === 'Set 3' && v.num === 254)!;
    expect(v).toBeDefined();
    expect(v.key).toBe('FE'.repeat(32));
  });

  it('round-trip sanity check passes for all 1284 vectors', () => {
    expect(() => parseNessieVectors(text)).not.toThrow();
  });
});
