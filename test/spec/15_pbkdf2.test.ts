/**
 * PBKDF2 tests
 * ============
 * Ported from pbkdf2_test.ts (Mocha/Chai) to Vitest in Phase 8.
 * Vectors: pbkdf2_vectors.ts (RFC 6070 SHA1 values; RFC 7914 §11 SHA256 values)
 */

import { describe, it, expect } from 'vitest';
import { PBKDF2 } from '../../src/pbkdf2';
import { Convert } from '../../src/base';
import { HMAC } from '../../src/hmac';
import { SHA256 } from '../../src/sha256';
import { vector } from './pbkdf2_vectors';

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
