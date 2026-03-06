//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          This file is part of the
//        ▄██████████████████████ ▀████▄      leviathan crypto library
//      ▄█████████▀▀▀     ▀███████▄▄███████▌
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  Repository
//     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Author: xero (https://x-e.ro)
//       ▀██████   ▄▄██            ▀▀  ██▄    License: MIT
//         ▀█████▄   ▄██▄             ▄▀▄▀
//            ▀████▄   ▄██▄                   +--------------+
//              ▐████   ▐███                  |     BKDF2    |
//       ▄▄██████████    ▐███         ▄▄      +--------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// BKDF2 Password-Based Key Derivation Function 2, takes a hash/HMAC function
// and generates a derived, streched password key due to iteration rounds.
// NOTE: At least a minimum of 10000 rounds are recommended!
//
// @deprecated Use {@link Argon2id} instead. PBKDF2 is CPU-bound only and
// vulnerable to GPU/ASIC parallel attacks. Argon2id is memory-hard and
// resistant to both GPU attacks and side-channel attacks.
import { Convert } from './base';
import { SHA256 } from './sha256';
import { HMAC } from './hmac';
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
export class PBKDF2 {
    hmac;
    rounds;
    /**
   * ctor
   * @param {KeyedHash} hmac HMAC function like HMAC-SHA1 or HMAC-SHA256
   * @param {Number} rounds Optional, number of iterations, defaults to 10000
   */
    constructor(hmac, rounds = 10000) {
        this.hmac = hmac;
        this.rounds = rounds;
    }
    /**
   * Generate derived key
   * @param {Uint8Array} password The password
   * @param {Uint8Array} salt The salt
   * @param {Number} length Optional, the derived key length (dkLen), defaults to the half of the HMAC block size
   * @return {Uint8Array} The derived key as byte array
   */
    hash(password, salt, length) {
        let u, ui;
        length = length || (this.hmac.hashSize >>> 1);
        const out = new Uint8Array(length);
        for (let k = 1, len = Math.ceil(length / this.hmac.hashSize); k <= len; k++) {
            u = ui = this.hmac.init(password).update(salt).digest(new Uint8Array([(k >>> 24) & 0xFF, (k >>> 16) & 0xFF, (k >>> 8) & 0xFF, k & 0xFF]));
            for (let i = 1; i < this.rounds; i++) {
                ui = this.hmac.hash(password, ui);
                for (let j = 0; j < ui.length; j++) {
                    u[j] ^= ui[j];
                }
            }
            // append data
            out.set(u.subarray(0, k * this.hmac.hashSize < length ? this.hmac.hashSize : length - (k - 1) * this.hmac.hashSize), (k - 1) * this.hmac.hashSize);
        }
        return out;
    }
    /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
    selftest() {
        const tv = {
            key: 'password',
            salt: 'salt',
            c: 2,
            sha256: 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
        };
        const pbkdf2_sha256 = new PBKDF2(new HMAC(new SHA256()), tv.c);
        const key = Convert.str2bin(tv.key);
        const salt = Convert.str2bin(tv.salt);
        const mac = pbkdf2_sha256.hash(key, salt, Convert.hex2bin(tv.sha256).length);
        // non-sensitive: selftest only — tv.sha256 is a hardcoded public test vector,
        // no attacker-controlled input can influence either side of this comparison
        return Convert.bin2hex(mac) === tv.sha256;
    }
}
