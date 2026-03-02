/**
 * Curve25519 / Ed25519 tests
 * ===========================
 * Ported from x25519_test.ts (Mocha/Chai) to Vitest in Phase 8.
 * Vectors: x25519_vectors.ts (4 sources: IETF draft, tweetnacl-js, djb NaCl,
 *          unknown Ed25519 source — all UNVERIFIED)
 *
 * Changes from original:
 * - assert.ok(x) → expect(x).toBeTruthy()
 * - assert.notOk(x) → expect(x).toBeFalsy()
 * - assert.equal(x, y) → expect(x).toBe(y)
 * - this.timeout(ms) → third arg to it()
 * - done callback removed (tests are synchronous)
 * - generateKeys() return typed as { pk, sk } | undefined (Phase 6 change)
 */

import { describe, it, expect } from 'vitest';
import { Curve25519, Ed25519 } from '../../src/x25519';
import { Convert } from '../../src/base';
import { generate_vector, random_vector, original_vector, ed25519_vector } from './x25519_vectors';

describe('curve25519', () => {
  const x25519  = new Curve25519();
  const ed25519 = new Ed25519();

  // -------------------------------------------------------------------------
  // x25519 — key generation KAT
  // -------------------------------------------------------------------------

  describe('x25519 - key generation (KAT)', () => {
    it(`check ${generate_vector.length} test vectors`, () => {
      for (const vec of generate_vector) {
        const sk = Convert.hex2bin(vec[0]);
        const pk = Convert.hex2bin(vec[1]);
        expect(x25519.generateKeys(sk)!.pk).toEqual(pk);
      }
    });
  });

  // -------------------------------------------------------------------------
  // x25519 — Monte Carlo key generation
  // Ref: https://code.google.com/p/go/source/browse/curve25519/curve25519_test.go?repo=crypto
  // -------------------------------------------------------------------------

  describe('x25519 - key generation (Monte Carlo Test)', () => {
    it(`200 chained generateKeys calls produce expected final value`, { timeout: 10000 }, () => {
      let input  = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
      const result = new Uint8Array([0x89, 0x16, 0x1f, 0xde, 0x88, 0x7b, 0x2b, 0x53,
                                     0xde, 0x54, 0x9a, 0xf4, 0x83, 0x94, 0x01, 0x06,
                                     0xec, 0xc1, 0x14, 0xd6, 0x98, 0x2d, 0xaa, 0x98,
                                     0x25, 0x6d, 0xe2, 0x3b, 0xdf, 0x77, 0x66, 0x1a]);
      for (let i = 0; i < 200; i++) {
        const keys = x25519.generateKeys(input);
        input = keys!.pk;
      }
      expect(input).toEqual(result);
    });
  });

  // -------------------------------------------------------------------------
  // x25519 — scalarMult
  // -------------------------------------------------------------------------

  describe('x25519 - scalarMult', () => {
    it(`check ${original_vector.length} original test vectors`, { timeout: 10000 }, () => {
      for (const vec of original_vector) {
        const sk  = Convert.hex2bin(vec[0]);
        const pk  = Convert.hex2bin(vec[1]);
        const out = Convert.hex2bin(vec[2]);
        expect(x25519.scalarMult(sk, pk)).toEqual(out);
      }
    });

    it(`check ${random_vector.length} random test vectors`, { timeout: 10000 }, () => {
      for (const vec of random_vector) {
        const pk1 = Convert.base642bin(vec[0])!;
        const sk1 = Convert.base642bin(vec[1])!;
        const pk2 = Convert.base642bin(vec[2])!;
        const sk2 = Convert.base642bin(vec[3])!;
        const out = Convert.base642bin(vec[4])!;
        sk1[ 0] &= 0xf8;
        sk1[31] &= 0x3f;
        sk1[31] |= 0x40;
        sk2[ 0] &= 0xf8;
        sk2[31] &= 0x3f;
        sk2[31] |= 0x40;
        expect(x25519.generateKeys(sk1)!.pk).toEqual(pk1);
        expect(x25519.generateKeys(sk2)!.pk).toEqual(pk2);
        expect(x25519.scalarMult(sk1, pk2)).toEqual(out);
        expect(x25519.scalarMult(sk2, pk1)).toEqual(out);
      }
    });
  });

  // -------------------------------------------------------------------------
  // x25519 — selftest
  // -------------------------------------------------------------------------

  describe('x25519 - selftest', () => {
    it('selftest passes', () => {
      expect(x25519.selftest()).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Ed25519 — key generation
  // -------------------------------------------------------------------------

  describe('ed25519 - key generation', () => {
    it(`check 256 test vectors`, { timeout: 10000 }, () => {
      for (let i = 0; i < 256; i++) {
        const sk = Convert.hex2bin(ed25519_vector[i].sk);
        const pk = Convert.hex2bin(ed25519_vector[i].pk);
        expect(ed25519.generateKeys(sk)!.pk).toEqual(pk);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Ed25519 — signing
  // -------------------------------------------------------------------------

  describe('ed25519 - signing', () => {
    it(`check 256 test vectors`, { timeout: 10000 }, () => {
      for (let i = 0; i < 256; i++) {
        const sk = Convert.hex2bin(ed25519_vector[i].sk);
        const pk = Convert.hex2bin(ed25519_vector[i].pk);
        const m  = Convert.hex2bin(ed25519_vector[i].m);
        const s  = Convert.hex2bin(ed25519_vector[i].s);
        expect(ed25519.sign(m, sk, pk)).toEqual(s);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Ed25519 — verify (positive and negative)
  // -------------------------------------------------------------------------

  describe('ed25519 - verify', () => {
    it('valid signatures pass; corrupted and short signatures fail', { timeout: 10000 }, () => {
      // Positive: all 256 valid signatures must verify
      for (let i = 0; i < 256; i++) {
        const pk = Convert.hex2bin(ed25519_vector[i].pk);
        const m  = Convert.hex2bin(ed25519_vector[i].m);
        const s  = Convert.hex2bin(ed25519_vector[i].s);
        expect(ed25519.verify(m, pk, s)).toBeTruthy();
      }

      // Negative: flip one bit in signature — must NOT verify
      for (let i = 0; i < 128; i++) {
        const pk = Convert.hex2bin(ed25519_vector[i].pk);
        const m  = Convert.hex2bin(ed25519_vector[i].m);
        const s  = Convert.hex2bin(ed25519_vector[i].s);
        s[i % 64] ^= 0x01;
        expect(ed25519.verify(m, pk, s)).toBeFalsy();
      }

      // Negative: truncated signature (63 bytes instead of 64) must NOT verify
      const pk63 = Convert.hex2bin(ed25519_vector[20].pk);
      const m63  = Convert.hex2bin(ed25519_vector[20].m);
      const s63  = Convert.hex2bin(ed25519_vector[20].s);
      expect(ed25519.verify(m63, pk63, s63.subarray(0, 63))).toBeFalsy();
    });
  });

  // -------------------------------------------------------------------------
  // Ed25519 — selftest
  // -------------------------------------------------------------------------

  describe('ed25519 - selftest', () => {
    it('selftest passes', () => {
      expect(ed25519.selftest()).toBe(true);
    });
  });

});
