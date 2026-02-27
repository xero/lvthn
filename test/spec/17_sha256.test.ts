/**
 * SHA-256 tests
 * =============
 * Ported from sha256_test.ts (Mocha/Chai) to Vitest in Phase 8.
 */

import { describe, it, expect } from 'vitest';
import { SHA256 } from '../../src/sha256';
import { Convert } from '../../src/base';
import { vector } from './sha256_vectors';

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
});
