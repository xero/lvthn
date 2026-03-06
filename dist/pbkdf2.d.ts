import { KeyedHash } from './base';
/**
 * PBKDF2 class
 *
 * @deprecated Use {@link Argon2id} instead. PBKDF2 is CPU-bound only and
 * vulnerable to GPU/ASIC parallel attacks. Argon2id is memory-hard and
 * resistant to both GPU attacks and side-channel attacks.
 *
 * Migration:
 * ```typescript
 * // Before (PBKDF2):
 * const key = new PBKDF2(new HMAC(new SHA256()), 210_000).hash(password, salt, 32);
 *
 * // After (Argon2id):
 * const { key } = await new Argon2id().deriveKey(password, salt);
 * ```
 *
 * PBKDF2 is retained for compatibility with existing encrypted data only.
 * Do not use it for new implementations.
 */
export declare class PBKDF2 {
    private hmac;
    private rounds;
    /**
   * ctor
   * @param {KeyedHash} hmac HMAC function like HMAC-SHA1 or HMAC-SHA256
   * @param {Number} rounds Optional, number of iterations, defaults to 10000
   */
    constructor(hmac: KeyedHash, rounds?: number);
    /**
   * Generate derived key
   * @param {Uint8Array} password The password
   * @param {Uint8Array} salt The salt
   * @param {Number} length Optional, the derived key length (dkLen), defaults to the half of the HMAC block size
   * @return {Uint8Array} The derived key as byte array
   */
    hash(password: Uint8Array, salt: Uint8Array, length?: number): Uint8Array;
    /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
    selftest(): boolean;
}
