/**
 * CTR Mode Test Vectors — Provenance Header
 * ==========================================
 *
 * What these vectors are:
 *   Authoritative Serpent-CTR test vectors for the leviathan TypeScript library.
 *   No official Serpent-CTR vectors exist in any public corpus — CTR mode was
 *   not included in the original AES candidate submission — so these vectors
 *   were derived from an independent C harness built on the verified reference
 *   implementation.
 *
 * How they were generated:
 *   Harness: sources/first_release_c_and_java/serpent/floppy1/ctr_harness.c
 *   Date   : 2026-02-27
 *   Platform: darwin-arm64 (Apple Silicon), macOS Darwin 25.3.0
 *   Compiler: Apple clang 17.0.0 (clang-1700.6.3.2), target arm64-apple-darwin25.3.0
 *
 *   To regenerate: build and run ctr_harness per the README in floppy1/.
 *     cd sources/first_release_c_and_java/serpent/floppy1
 *     make ctr_harness && ./ctr_harness
 *
 * Why floppy1:
 *   Ross Anderson's floppy1 (AES submission format) uses the same byte ordering
 *   as leviathan — bytes are reversed before packing as 32-bit LE words.  Using
 *   floppy1 means harness inputs and outputs can be compared to leviathan directly
 *   without any byte-order conversion.  floppy1 also produced floppy4's
 *   authoritative ECB/CBC vectors, so its ECB correctness was independently
 *   verified before the CTR harness was built on top of it.
 *
 *   Alternative (sources/serpent/serpent.c) was not used: it uses NESSIE byte
 *   ordering (big-endian per-word), incompatible with leviathan without conversion.
 *
 * Provenance chain:
 *   floppy1 reference ECB  -->  ctr_harness.c  -->  hardcoded vectors below
 *                                                -->  leviathan test suite (here)
 *
 * Reference sources branch:
 *   The full floppy1 reference sources (including ctr_harness.c and this
 *   provenance documentation) live in the reference-sources branch.
 *
 * ECB cross-corpus sanity:
 *   The "Cross-corpus ECB sanity" tests at the bottom of this file tie these
 *   CTR vectors back to the independently-verified floppy4 AES submission ECB
 *   corpus.  For all-zero plaintext, CT block 0 = ECB_encrypt(key, IV), which
 *   is confirmed against floppy4 KAT values:
 *     Case A (128-bit zero key): block 0 = E9BA668276B81896D093A9E67AB12036
 *     Case B (256-bit zero key): block 0 = 8910494504181950F98DD998A82B6749
 */

import { describe, it, expect } from 'vitest';
import { Serpent_CTR } from '../../src/serpent';
import { Serpent } from '../../src/serpent';
import { Convert } from '../../src/base';

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function hex(bytes: Uint8Array): string {
  return Convert.bin2hex(bytes).toUpperCase();
}

function h2b(s: string): Uint8Array {
  return Convert.hex2bin(s);
}

// ---------------------------------------------------------------------------
// Hardcoded CTR vectors (from ctr_harness.c output)
// ---------------------------------------------------------------------------

interface CtrVector {
  label:   string;
  keyHex:  string;
  ivHex:   string;
  ptHex:   string;
  ctHex:   string;
  blocks:  number;
}

const VECTORS: CtrVector[] = [
  {
    label:  'A',
    keyHex: '00000000000000000000000000000000',                            // 128-bit all-zero key
    ivHex:  '00000000000000000000000000000000',
    ptHex:  '000000000000000000000000000000000000000000000000' +           // 3 blocks all-zero PT
            '000000000000000000000000000000000000000000000000',
    ctHex:  'E9BA668276B81896D093A9E67AB12036' +                          // block 0
            'BC0ABF8C2037A9263586DE6BA1CEED9B' +                          // block 1
            '0F250F3B1F294E54A3E34512B0AB5D0C',                           // block 2
    blocks: 3,
  },
  {
    label:  'B',
    keyHex: '0000000000000000000000000000000000000000000000000000000000000000', // 256-bit all-zero key
    ivHex:  '00000000000000000000000000000000',
    ptHex:  '000000000000000000000000000000000000000000000000' +
            '000000000000000000000000000000000000000000000000',
    ctHex:  '8910494504181950F98DD998A82B6749' +                          // block 0 = ECB(zero-256,zero)
            '9FAA1E723BE36AA803321C2383DE86AD' +                          // block 1
            '0A3E7E267FBEF117CE63FCB3F0092CBC',                           // block 2
    blocks: 3,
  },
  {
    label:  'C',
    keyHex: '00000000000000000000000000000000',                            // 128-bit all-zero key
    ivHex:  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',                            // all-FF IV (counter wrap test)
    ptHex:  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +                          // 2 blocks all-FF PT
            'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    ctHex:  '1694760FECE869FDFA46403BF189B54D' +                         // block 0 (ctr=0xFF×16)
            '1645997D8947E7692F6C5619854EDFC9',                           // block 1 (ctr wrapped to 0x00×16)
    blocks: 2,
  },
  {
    label:  'D',
    keyHex: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', // 256-bit key
    ivHex:  '000102030405060708090A0B0C0D0E0F',
    ptHex:  '000102030405060708090A0B0C0D0E0F' +
            '101112131415161718191A1B1C1D1E1F',
    ctHex:  '64A81834E99AE14EA0477CDDF90076E1' +
            '78B4FA40E07C3157F13E8E77855C8EDA',
    blocks: 2,
  },
  {
    label:  'E',
    keyHex: '000000000000000000000000000000000000000000000000', // 192-bit all-zero key
    ivHex:  '00000000000000000000000000000000',
    ptHex:  '000000000000000000000000000000000000000000000000' +
            '000000000000000000000000000000000000000000000000',
    ctHex:  '42046B25C85DBD6B402B296A97EF83A5' +
            '47402E1C09E0C315B13CAB5A5AA17E49' +
            '9DCAABB7839129739D1C6F5501624E44',
    blocks: 3,
  },
];

// ---------------------------------------------------------------------------
// Helpers: extract a 16-byte block from a hex string
// ---------------------------------------------------------------------------

function block(hexStr: string, n: number): string {
  return hexStr.slice(n * 32, (n + 1) * 32);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Serpent-CTR authoritative vectors', () => {
  const serpentCtr = new Serpent_CTR();

  for (const v of VECTORS) {
    const key = h2b(v.keyHex);
    const iv  = h2b(v.ivHex);
    const pt  = h2b(v.ptHex);
    const ct  = h2b(v.ctHex);

    it(`Case ${v.label} — encrypt`, () => {
      expect(hex(serpentCtr.encrypt(key, pt, iv))).toBe(v.ctHex);
    });

    it(`Case ${v.label} — decrypt`, () => {
      expect(hex(serpentCtr.decrypt(key, ct, iv))).toBe(v.ptHex);
    });

    if (v.blocks >= 3) {
      it(`Case ${v.label} — block boundary: blocks 0/1/2 are distinct (counter increments)`, () => {
        const ctHex = hex(serpentCtr.encrypt(key, pt, iv));
        const b0 = block(ctHex, 0);
        const b1 = block(ctHex, 1);
        const b2 = block(ctHex, 2);
        expect(b0).not.toBe(b1);
        expect(b0).not.toBe(b2);
        expect(b1).not.toBe(b2);
      });
    }
  }

  // -------------------------------------------------------------------------
  // IV independence tests (Cases A and B: all-zero PT)
  // -------------------------------------------------------------------------

  it('Case A — IV independence: different IV produces different ciphertext', () => {
    const key    = h2b(VECTORS[0].keyHex);
    const pt     = h2b(VECTORS[0].ptHex);
    const ivZero = h2b(VECTORS[0].ivHex);                        // all-zero IV
    const ivOther = new Uint8Array(16); ivOther[15] = 0x01;      // IV = 0x00...01
    const ct1 = hex(serpentCtr.encrypt(key, pt, ivZero));
    const ct2 = hex(serpentCtr.encrypt(key, pt, ivOther));
    expect(ct1).not.toBe(ct2);
  });

  it('Case B — IV independence: different IV produces different ciphertext', () => {
    const key     = h2b(VECTORS[1].keyHex);
    const pt      = h2b(VECTORS[1].ptHex);
    const ivZero  = h2b(VECTORS[1].ivHex);
    const ivOther = new Uint8Array(16); ivOther[0] = 0x01;
    const ct1 = hex(serpentCtr.encrypt(key, pt, ivZero));
    const ct2 = hex(serpentCtr.encrypt(key, pt, ivOther));
    expect(ct1).not.toBe(ct2);
  });

  // -------------------------------------------------------------------------
  // Cross-corpus ECB sanity check
  //
  // Ties these CTR tests back to the verified AES-submission ECB corpus.
  // For CTR with all-zero PT, CT == raw keystream.
  // keystream_block_0 = ECB_encrypt(key, counter_0) = ECB_encrypt(key, IV).
  // We verify this against Case A (128-bit key) and Case B (256-bit key).
  // -------------------------------------------------------------------------

  it('Cross-corpus ECB sanity: Case A block 0 CT = ECB_encrypt(all-zero-128-key, all-zero-counter)', () => {
    const s      = new Serpent();
    const key    = h2b(VECTORS[0].keyHex);   // all-zero 128-bit key
    const ctrBlk = new Uint8Array(16);        // all-zero counter (= all-zero IV)
    const ecbKS  = hex(s.encrypt(key, ctrBlk));
    // Case A PT is all-zero, so CT block 0 == keystream block 0 == ECB output
    const caseAblock0 = block(VECTORS[0].ctHex, 0);
    expect(ecbKS).toBe(caseAblock0);         // must be E9BA668276B81896D093A9E67AB12036
  });

  it('Cross-corpus ECB sanity: Case B block 0 CT = ECB_encrypt(all-zero-256-key, all-zero-counter)', () => {
    const s      = new Serpent();
    const key    = h2b(VECTORS[1].keyHex);   // all-zero 256-bit key
    const ctrBlk = new Uint8Array(16);        // all-zero counter
    const ecbKS  = hex(s.encrypt(key, ctrBlk));
    const caseBblock0 = block(VECTORS[1].ctHex, 0);
    expect(ecbKS).toBe(caseBblock0);         // must be 8910494504181950F98DD998A82B6749
  });
});
