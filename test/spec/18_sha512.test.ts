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
// SHA-512 tests
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { SHA512 } from '../../src/sha512';
import { Convert } from '../../src/base';
import { vector } from '../vectors/sha512_vectors';

describe('SHA512', () => {
  const sha = new SHA512();

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
      const cumulative = new SHA512();
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
      expect(hash).toBe('602923787640dd6d77a99b101c379577a4054df2d61f39c74172cafa2d9f5b26a11b40b7ba4cdc87e84a4ab91b85391cb3e1c0200f3e3d5e317486aae7bebbf3');
    });
  });

  describe('selftest', () => {
    it('selftest passes', () => {
      expect(sha.selftest()).toBe(true);
    });
  });
});
