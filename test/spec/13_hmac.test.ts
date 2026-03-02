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
// HMAC tests
// HMAC-SHA1 tests were DROPPED: HMAC_SHA1 is not exported from src/hmac.ts
// because src/sha1.ts was removed from the library. The hmac_vectors.ts file
// retains mac1 fields but they are unused here.
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { HMAC, HMAC_SHA256, HMAC_SHA512 } from '../../src/hmac';
import { SHA256 } from '../../src/sha256';
import { Convert } from '../../src/base';
import { vector } from './hmac_vectors';

describe('HMAC', () => {

  describe('input unaltered after hash', () => {
    it(`key and data arrays are not mutated by HMAC (${vector.length} vectors)`, () => {
      for (const v of vector) {
        const key  = Convert.hex2bin(v.key);
        const data = Convert.hex2bin(v.data);
        (new HMAC(new SHA256())).hash(key, data);
        expect(Convert.bin2hex(key)).toEqual(v.key);
        expect(Convert.bin2hex(data)).toEqual(v.data);
      }
    });
  });

  describe('HMAC-SHA256', () => {
    const hmac = new HMAC_SHA256();
    it(`check ${vector.length} test vectors`, () => {
      for (const v of vector) {
        expect(hmac.hash(Convert.hex2bin(v.key), Convert.hex2bin(v.data))).toEqual(Convert.hex2bin(v.mac256));
      }
    });
  });

  describe('HMAC-SHA512', () => {
    const hmac = new HMAC_SHA512();
    it(`check ${vector.length} test vectors`, () => {
      for (const v of vector) {
        expect(hmac.hash(Convert.hex2bin(v.key), Convert.hex2bin(v.data))).toEqual(Convert.hex2bin(v.mac512));
      }
    });
  });

  /**
   * RFC 4231 HMAC-SHA-256 test vectors.
   * Source: https://www.rfc-editor.org/rfc/rfc4231
   */
  describe('RFC 4231 HMAC-SHA256 vectors', () => {
    const hmac = new HMAC_SHA256();
    const fromHex = (hex: string) => Convert.hex2bin(hex);

    it('Test Case 1 — "Hi There" with 20-byte key', () => {
      const mac = hmac.hash(
        fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
        fromHex('4869205468657265'),
      );
      expect(Convert.bin2hex(mac)).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    });

    it('Test Case 2 — "what do ya want for nothing?" with key "Jefe"', () => {
      const mac = hmac.hash(
        fromHex('4a656665'),
        fromHex('7768617420646f2079612077616e7420666f72206e6f7468696e673f'),
      );
      expect(Convert.bin2hex(mac)).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    });

    it('Test Case 5 — key longer than block size (131 bytes) triggers key hashing', () => {
      const mac = hmac.hash(
        fromHex('aa'.repeat(131)),
        fromHex('54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374'),
      );
      expect(Convert.bin2hex(mac)).toBe('60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
    });
  });

});
