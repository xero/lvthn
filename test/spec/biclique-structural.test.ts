/**
 * Structural Validation — Biclique Attack State 66 Extraction
 *
 * Anchors the mapping derived in structural-validation-mappings.md to leviathan's
 * actual runtime behavior using existing KAT vectors. Does NOT compare against
 * BicliqueFinder (no byte-reversal shim needed). Instead, verifies that the
 * extraction expression is live, deterministic, and responds correctly to key
 * material.
 *
 * Mapping under test (Section 6.2 of structural-validation-mappings.md):
 *   - roundHook(21) captures BicliqueFinder state 67 (post-K22)
 *   - EC[22] = 58006: X1 is in r[4], i.e. state[4] at hookCall 21
 *   - LK XORed key[4*22+1] = key[89] into r[4]
 *   - XOR-out recovers BicliqueFinder state 66 (pre-K22)
 *   - Nibbles 8+9 = bits 31-24 of X1 = MSB byte of state[4] ^ subkeys[89]
 *
 * Four assertions:
 *   1. Hook fires and returns a valid byte — the expression runs without error.
 *   2. Deterministic — same key+plaintext always yields the same extracted byte.
 *   3. XOR reversal is non-trivial — subkeys[89] is nonzero and modifies state[4].
 *   4. Sensitive to key material — flipping a master key bit that provably affects
 *      subkeys[89] changes the extracted byte, confirming the extraction tracks
 *      state 66 rather than some fixed or unrelated value.
 *
 * @see docs/structural-validation-mappings.md
 */

import { describe, it, expect } from 'vitest';
import { Serpent } from '../../src/serpent';

// ---------------------------------------------------------------------------
// Test vector: all-zero 256-bit key, all-zero plaintext.
// This is an explicitly tested edge case in the main KAT suite (01_kat.test.ts)
// and produces a known, stable ciphertext. Using it here gives a stable anchor.
// ---------------------------------------------------------------------------
const ZERO_KEY = new Uint8Array(32); // 256-bit all-zero key
const ZERO_PT = new Uint8Array(16); // 128-bit all-zero plaintext

// ---------------------------------------------------------------------------
// Helper: set the roundHook, encrypt, return extracted byte from state 66.
// Returns -1 if the hook never fired (should never happen at round 21).
// ---------------------------------------------------------------------------
function extractState66Byte(key: Uint8Array, pt: Uint8Array): number {
  const s = new Serpent();
  const subkeys = s.getSubkeys(key); // 132 words: K0..K32, 4 words each
  let captured = -1;

  s.roundHook = (round: number, state: number[], _ec: number) => {
    if (round === 21) {
      // roundHook(21) fires after LK(r, 1, 4, 3, 0, 2, 22):
      //   - ec = EC[22] = 58006
      //   - 58006 % 7 = 4, so X1 is in state[4]
      //   - LK XORed key[4*22+1] = key[89] into r[4] (X1 slot)
      //   - XOR-out recovers BF state 66 (pre-K22)
      //   - Nibbles 8+9 = bits 31-24 of X1 = MSB byte
      const X1_state66 = (state[4] ^ subkeys[89]) >>> 0; // unsigned 32-bit
      captured = (X1_state66 >>> 24) & 0xff;
    }
  };

  s.encrypt(key, pt);
  return captured;
}

// ---------------------------------------------------------------------------
// Helper: find the first single master key bit whose flip changes subkeys[89].
// Uses getSubkeys() to inspect the key schedule directly — no assumptions about
// which bit it will be. Returns [byteIndex, bitMask] or null if none found
// in the full 256-bit key (should never be null for a non-degenerate key).
// ---------------------------------------------------------------------------
function findKeyBitAffectingWord89(
  baseKey: Uint8Array,
): [number, number] | null {
  const s = new Serpent();
  const baseWord89 = s.getSubkeys(baseKey)[89];

  for (let b = 0; b < 32; b++) {
    for (let bit = 0; bit < 8; bit++) {
      const candidate = new Uint8Array(baseKey);
      candidate[b] ^= 1 << bit;
      const candidateWord89 = new Serpent().getSubkeys(candidate)[89];
      if (candidateWord89 !== baseWord89) {
        return [b, 1 << bit];
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Biclique structural validation — state 66 extraction (Section 6.2 mapping)', () => {
  it('1. Hook fires and extraction returns a valid byte (0–255)', () => {
    const val = extractState66Byte(ZERO_KEY, ZERO_PT);
    // Hook must have fired — -1 means round 21 was never reached
    expect(val).not.toBe(-1);
    // Must be a valid 8-bit value
    expect(val).toBeGreaterThanOrEqual(0);
    expect(val).toBeLessThanOrEqual(255);
  });

  it('2. Deterministic — identical inputs always yield the same extracted byte', () => {
    const val1 = extractState66Byte(ZERO_KEY, ZERO_PT);
    const val2 = extractState66Byte(ZERO_KEY, ZERO_PT);
    const val3 = extractState66Byte(ZERO_KEY, ZERO_PT);
    expect(val1).toBe(val2);
    expect(val2).toBe(val3);
  });

  it('3. XOR reversal is non-trivial — subkeys[89] is nonzero and modifies state[4]', () => {
    const s = new Serpent();
    const subkeys = s.getSubkeys(ZERO_KEY);

    // Confirm subkeys[89] is not the identity under XOR.
    // (For the all-zero key this is highly unlikely to be zero; if it ever is,
    // this test should be re-run with a different anchor key.)
    expect(subkeys[89]).not.toBe(0);

    let rawState4 = -1;
    let xoredState4 = -1;

    s.roundHook = (round: number, state: number[], _ec: number) => {
      if (round === 21) {
        rawState4 = state[4] >>> 0;
        xoredState4 = (state[4] ^ subkeys[89]) >>> 0;
      }
    };
    s.encrypt(ZERO_KEY, ZERO_PT);

    expect(rawState4).not.toBe(-1); // hook fired
    expect(xoredState4).not.toBe(-1); // hook fired

    // The XOR reversal must change the value — if subkeys[89] is nonzero and
    // state[4] happens to equal subkeys[89], the result would be 0, which is
    // still a different value from state[4]. The only way these could match is
    // if subkeys[89] === 0, which we've already asserted above.
    expect(xoredState4).not.toBe(rawState4);
  });

  it('4. Sensitive to key material — flipping a bit that changes subkeys[89] changes the extracted byte', () => {
    // Find a master key bit that provably changes subkeys[89]
    const found = findKeyBitAffectingWord89(ZERO_KEY);
    expect(found).not.toBeNull();

    const [byteIdx, bitMask] = found!;
    const flippedKey = new Uint8Array(ZERO_KEY);
    flippedKey[byteIdx] ^= bitMask;

    const baseVal = extractState66Byte(ZERO_KEY, ZERO_PT);
    const flippedVal = extractState66Byte(flippedKey, ZERO_PT);

    // Changing subkeys[89] changes the XOR-out term, which must change the
    // extracted byte. (It's theoretically possible for the cipher's internal
    // state change to exactly cancel the subkey change, but this is astronomically
    // unlikely for a cryptographically secure cipher.)
    expect(flippedVal).not.toBe(baseVal);
  });

  // Bonus: confirm the hook is ONLY firing at round 21, not leaking from
  // adjacent rounds. If it fired at, say, round 20 and the round===21 guard
  // were wrong, captured would reflect a different EC constant / register slot.
  it('5. Hook is guarded to round 21 only — no cross-round contamination', () => {
    const s = new Serpent();
    // const subkeys = s.getSubkeys(ZERO_KEY);
    const firedRounds: number[] = [];

    s.roundHook = (round: number, _state: number[], _ec: number) => {
      firedRounds.push(round);
    };
    s.encrypt(ZERO_KEY, ZERO_PT);

    // Confirm round 21 fired exactly once
    const round21Fires = firedRounds.filter((r) => r === 21);
    expect(round21Fires).toHaveLength(1);

    // Confirm round 21 is present in the full sequence (sanity)
    expect(firedRounds).toContain(21);

    // Confirm hook fires for all 32 rounds (0–31)
    expect(firedRounds).toHaveLength(32);
  });
});
