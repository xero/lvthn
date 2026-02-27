/**
 * HMAC tests
 * ==========
 * Ported from hmac_test.ts (Mocha/Chai) to Vitest in Phase 8.
 *
 * HMAC-SHA1 tests were DROPPED: HMAC_SHA1 is not exported from src/hmac.ts
 * because src/sha1.ts was removed from the library. The hmac_vectors.ts file
 * retains mac1 fields but they are unused here.
 */

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

});
