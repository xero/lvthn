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
// PBKDF2 tests
// Vectors: pbkdf2_vectors.ts (RFC 6070 SHA1 values; RFC 7914 §11 SHA256 values)
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { PBKDF2 } from '../../src/pbkdf2';
import { Convert } from '../../src/base';
import { HMAC } from '../../src/hmac';
import { SHA256 } from '../../src/sha256';
import { vector } from '../vectors/pbkdf2_vectors';

describe('PBKDF2', () => {
  describe('HMAC-SHA256', () => {
    it(`check ${vector.length} test vectors`, () => {
      for (const v of vector) {
        const pbkdf2 = new PBKDF2(new HMAC(new SHA256()), v.c);
        const key  = Convert.str2bin(v.key);
        const salt = Convert.str2bin(v.salt);
        const mac  = pbkdf2.hash(key, salt, Convert.hex2bin(v.sha256).length);
        expect(mac).toEqual(Convert.hex2bin(v.sha256));
      }
    });
  });

  describe('selftest', () => {
    it('selftest passes', () => {
      const pbkdf2 = new PBKDF2(new HMAC(new SHA256()));
      expect(pbkdf2.selftest()).toBe(true);
    });
  });
});
