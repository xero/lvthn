/**
 * UUID tests (V1 and V4)
 * =======================
 * Ported from uuid_test.ts (Mocha/Chai) to Vitest in Phase 8.
 */

import { describe, it, expect } from 'vitest';
import { UUID } from '../../src/uuid';

describe('UUID', () => {
  const uuid = new UUID();

  describe('V1 generation', () => {
    it('produces 16-byte arrays that differ by node ID', () => {
      const id1 = uuid.v1(new Uint8Array([0, 1, 2, 3, 4, 5]));
      const id2 = uuid.v1(new Uint8Array([1, 1, 2, 3, 4, 5]));
      expect(id1).toBeDefined();
      expect(id1!.length).toBe(16);
      expect(id2).toBeDefined();
      expect(id2!.length).toBe(16);
      expect(id1).not.toEqual(id2);

      const id3 = uuid.v1(new Uint8Array([0x55, 0xAA, 0, 1, 2, 3]));
      expect(id3).toBeDefined();
      expect(id3!.length).toBe(16);
      // node ID bytes appear at positions 10–15
      expect(id3![10]).toBe(0x55);
      expect(id3![11]).toBe(0xAA);
    });
  });

  describe('V4 generation', () => {
    it('produces 16-byte arrays that differ for different random inputs', () => {
      const id1 = uuid.v4(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]));
      const id2 = uuid.v4(new Uint8Array([1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]));
      expect(id1).toBeDefined();
      expect(id1!.length).toBe(16);
      expect(id2).toBeDefined();
      expect(id2!.length).toBe(16);
      expect(id1).not.toEqual(id2);
    });
  });
});
