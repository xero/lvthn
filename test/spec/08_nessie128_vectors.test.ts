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
// Full NESSIE Serpent-128-128 vector suite (1028 vectors)
//
// Vector source: Serpent-128-128.verified.test-vectors.txt
// @see https://www.cosic.esat.kuleuven.be/nessie/testvectors/
// mirror @see biham.cs.technion.ac.il/Reports/Serpent
//
// The same byte-reversal preprocessing used for Serpent-256 applies here:
//   - Key:        reverse all 16 bytes (NESSIE big-endian → leviathan AES-submission)
//   - Plaintext:  reverse all bytes
//   - Ciphertext: reverse all bytes
//
// Empirically verified: Set 1 v#0 (128-bit key=80000000..., plain=0..0,
// cipher=264E5481EFF42A4606ABDA06C0BFDA3D) passes with this preprocessing.
//
// Run AFTER 06_nessie_helpers.test.ts and 07_nessie_vectors.test.ts.
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

function hex(bytes: Uint8Array): string {
  return Convert.bin2hex(bytes).toUpperCase();
}

// ---------------------------------------------------------------------------
// Load and parse once for all tests
// ---------------------------------------------------------------------------

const VECTORS_DIR = resolve(__dirname, '../vectors');
const text = readFileSync(
  resolve(VECTORS_DIR, 'Serpent-128-128.verified.test-vectors.txt'),
  'utf8'
);
const vectors = parseNessieVectors(text);
const s = new Serpent();

// ---------------------------------------------------------------------------
// Sanity: confirm parser found the expected count
// ---------------------------------------------------------------------------

describe('NESSIE Serpent-128-128 — parser', () => {
  it('parses exactly 1028 vectors', () => {
    expect(vectors.length).toBe(1028);
  });

  it('Set 1, v#0 has correct fields', () => {
    const v = vectors.find(v => v.set === 'Set 1' && v.num === 0)!;
    expect(v).toBeDefined();
    expect(v.key).toBe('80000000000000000000000000000000');
    expect(v.plain).toBe('00000000000000000000000000000000');
    expect(v.cipher).toBe('264E5481EFF42A4606ABDA06C0BFDA3D');
  });
});

// ---------------------------------------------------------------------------
// Encrypt: for every vector, encrypt(plain) should equal cipher
// ---------------------------------------------------------------------------

describe('NESSIE Serpent-128-128 — encrypt (all 1028 vectors)', () => {
  for (const v of vectors) {
    it(`${v.set}, v#${v.num} — encrypt`, () => {
      const key    = prepareNessieKey(v.key);
      const pt     = prepareNessiePlaintext(v.plain);
      const expCT  = prepareNessieCiphertext(v.cipher);
      expect(hex(s.encrypt(key, pt))).toBe(hex(expCT));
    });
  }
});

// ---------------------------------------------------------------------------
// Decrypt: for every vector, decrypt(cipher) should equal plain
// ---------------------------------------------------------------------------

describe('NESSIE Serpent-128-128 — decrypt (all 1028 vectors)', () => {
  for (const v of vectors) {
    it(`${v.set}, v#${v.num} — decrypt`, () => {
      const key    = prepareNessieKey(v.key);
      const ct     = prepareNessieCiphertext(v.cipher);
      const expPT  = prepareNessiePlaintext(v.plain);
      expect(hex(s.decrypt(key, ct))).toBe(hex(expPT));
    });
  }
});
