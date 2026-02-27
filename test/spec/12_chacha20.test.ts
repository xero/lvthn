/**
 * ChaCha20 tests
 * ==============
 * Ported from chacha20_test.ts (Mocha/Chai) to Vitest in Phase 8.
 */

import { describe, it, expect } from 'vitest';
import { ChaCha20 } from '../../src/chacha20';
import { Convert } from '../../src/base';
import { vector } from './chacha20_vectors';

describe('ChaCha20', () => {
  const chacha = new ChaCha20();

  describe('encrypt', () => {
    it(`check ${vector.length} test vectors`, () => {
      for (const v of vector) {
        const pt = typeof v.pt !== 'undefined'
          ? Convert.hex2bin(v.pt)
          : new Uint8Array(v.ct.length / 2);
        const out = chacha.encrypt(Convert.hex2bin(v.key), pt, Convert.hex2bin(v.iv), v.ibc);
        expect(out).toEqual(Convert.hex2bin(v.ct));
      }
    });
  });

  describe('decrypt', () => {
    it(`check ${vector.length} test vectors`, () => {
      for (const v of vector) {
        const pt = typeof v.pt !== 'undefined'
          ? Convert.hex2bin(v.pt)
          : new Uint8Array(v.ct.length / 2);
        const out = chacha.decrypt(Convert.hex2bin(v.key), Convert.hex2bin(v.ct), Convert.hex2bin(v.iv), v.ibc);
        expect(out).toEqual(pt);
      }
    });
  });
});
