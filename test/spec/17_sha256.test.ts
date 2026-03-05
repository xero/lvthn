///////////////////////////////////////////////////////////////////////////////
//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          This file is part of the
//        ▄██████████████████████ ▀████▄      leviathan crypto library
//      ▄█████████▀▀▀     ▀███████▄▄███████▌
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  Repository
//     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Author: xero (https://x-e.ro)
//       ▀██████   ▄▄██            ▀▀  ██▄    License: MIT
//         ▀█████▄   ▄██▄             ▄▀▄▀
//            ▀████▄   ▄██▄                   +---------------+
//              ▐████   ▐███                  |   TEST SPEC   |
//       ▄▄██████████    ▐███         ▄▄      +---------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// SHA256 Tests
//
// FIPS 180-4 §6.2 test vectors.
// Source: NIST FIPS PUB 180-4, Secure Hash Standard.
// @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//
// Iterative test from the sjcl project — hashes 1000 strings, accumulates
// all intermediate hashes into a final cumulative hash, compares to a
// pre-computed expected value.
// @see https://github.com/bitwiseshiftleft/sjcl/blob/master/test/sha256_test_brute_force.js
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { SHA256 } from '../../src/sha256';
import { Convert } from '../../src/base';
import { vector } from '../vectors/sha256_vectors';

describe('SHA256', () => {
  const sha = new SHA256();

  describe('hash', () => {
    it(`check ${vector.length} test vectors (one-shot)`, () => {
      for (const [pt, ct] of vector) {
        expect(Convert.bin2hex(sha.hash(Convert.str2bin(pt)))).toEqual(ct);
      }
    });
  });

  describe('update', () => {
    it(`check ${vector.length} test vectors (byte-by-byte update)`, () => {
      for (const [pt, ct] of vector) {
        sha.init();
        for (let j = 0; j < pt.length; j++) {
          sha.update(Convert.str2bin(pt.charAt(j)));
        }
        expect(Convert.bin2hex(sha.digest())).toEqual(ct);
      }
    });
  });

  /**
   * Iterative test from the sjcl project — hashes 1000 strings, accumulates
   * all intermediate hashes into a final cumulative hash, compares to a
   * pre-computed expected value.
   */
  describe('iteration', () => {
    it('cumulative hash of 1000 iterative hashes matches expected', () => {
      const cumulative = new SHA256();
      let toBeHashed = '';
      let hash: string;
      for (let i = 0; i < 10; i++) {
        for (let n = 100 * i; n < 100 * (i + 1); n++) {
          hash = Convert.bin2hex(sha.hash(Convert.str2bin(toBeHashed)));
          cumulative.update(Convert.str2bin(hash));
          toBeHashed = (hash.substring(0, 2) + toBeHashed).substring(0, n + 1);
        }
      }
      hash = Convert.bin2hex(cumulative.digest());
      expect(hash).toBe('f305c76d5d457ddf04f1927166f5e13429407049a5c5f29021916321fcdcd8b4');
    });
  });

  describe('selftest', () => {
    it('selftest passes', () => {
      expect(sha.selftest()).toBe(true);
    });
  });

  /**
   * FIPS 180-4 §6.2 test vectors.
   * Source: NIST FIPS PUB 180-4, Secure Hash Standard.
   */
  describe('FIPS 180-4 vectors', () => {
    it('empty string', () => {
      expect(Convert.bin2hex(sha.hash())).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    it('"abc"', () => {
      expect(Convert.bin2hex(sha.hash(Convert.str2bin('abc')))).toBe(
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    it('"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"', () => {
      expect(Convert.bin2hex(sha.hash(Convert.str2bin('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))).toBe(
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
      );
    });

    it('1,000,000 repetitions of "a"', () => {
      sha.init();
      const chunk = Convert.str2bin('a'.repeat(1000));
      for (let i = 0; i < 1000; i++) {
        sha.update(chunk);
      }
      expect(Convert.bin2hex(sha.digest())).toBe(
        'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
      );
    });
  });
});
