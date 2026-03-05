import { Blockcipher } from './base';
export declare class CBC {
    blockcipher: Blockcipher;
    /**
     * CBC ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    constructor(blockcipher: Blockcipher);
    /**
     * CBC mode encryption
     */
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    /**
     * CBC mode decryption
     */
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
export declare class CTR {
    blockcipher: Blockcipher;
    ctr: Uint8Array;
    /**
     * CTR ctor
     * @param {Object} blockcipher The block cipher algorithm to use
     */
    constructor(blockcipher: Blockcipher);
    /**
     * CTR mode encryption
     */
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    /**
     * CTR mode decryption
     */
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
}
/**
 * ChaCha20 block function per RFC 8439 §2.3 — IETF variant.
 * Accepts a 256-bit key, 32-bit counter, and 96-bit (12-byte) nonce.
 * Returns 64 bytes of keystream.
 *
 * NOTE: This is the IETF ChaCha20, not the original Bernstein variant
 * (which uses a 64-bit nonce and 64-bit counter). The existing ChaCha20
 * class uses the original variant; this function is needed for AEAD.
 */
export declare function _chacha20Block(key: Uint8Array, counter: number, nonce12: Uint8Array): Uint8Array;
/**
 * HChaCha20 subkey derivation per XChaCha20 IETF draft §2.2.
 *
 * Differs from chacha20Block:
 * - Takes a 16-byte input (all 4 of state words 12-15 are filled by nonce16)
 * - Does NOT add initial state to output
 * - Returns only first row (words 0-3) and last row (words 12-15) — 32 bytes total
 */
export declare function _hchacha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array;
/**
 * Poly1305 MAC per RFC 8439 §2.5.
 *
 * Uses BigInt for clarity (not limb arithmetic) — RFC 8439 §3 notes that
 * a naive big-number implementation will not exceed 2^288 and is correct.
 *
 * IMPORTANT: `key` is a 32-byte ONE-TIME key (r || s).
 * This key MUST NEVER be reused across messages. In the AEAD construction
 * it is derived fresh for each message from ChaCha20 at counter=0.
 *
 * @param key     32-byte one-time key: first 16 bytes = r (clamped), last 16 = s
 * @param message arbitrary-length message to authenticate
 * @returns       16-byte tag
 */
export declare function _poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array;
/**
 * Generate the Poly1305 one-time key for a given (key, nonce) pair.
 * Calls ChaCha20 at counter=0 and takes the first 32 bytes (RFC 8439 §2.6).
 */
export declare function _poly1305KeyGen(key: Uint8Array, nonce12: Uint8Array): Uint8Array;
/**
 * AEAD_CHACHA20_POLY1305 per RFC 8439.
 *
 * Combined authenticated encryption: ChaCha20 for confidentiality,
 * Poly1305 for integrity and authenticity. Standardized in RFC 8439;
 * used in TLS 1.3, WireGuard, and SSH.
 *
 * **Nonce uniqueness is critical.** Reusing a (key, nonce) pair destroys
 * confidentiality: XOR of two ciphertexts = XOR of two plaintexts.
 * The 96-bit nonce is too short for random generation at scale.
 * Prefer {@link XChaCha20Poly1305} when nonces are generated randomly.
 *
 * Key:   256-bit (32 bytes)
 * Nonce: 96-bit (12 bytes) — use a counter or derive deterministically
 */
export declare class ChaCha20Poly1305 {
    /**
     * Encrypt and authenticate plaintext.
     *
     * @param key       256-bit key (32 bytes)
     * @param nonce     96-bit nonce (12 bytes). MUST be unique per (key, message).
     *                  Use a counter or derive deterministically. Do NOT generate
     *                  randomly — use XChaCha20Poly1305 for random nonces.
     * @param plaintext message to encrypt (any length including zero)
     * @param aad       additional authenticated data (not encrypted, authenticated)
     * @returns `{ ciphertext, tag }` — ciphertext.length === plaintext.length, tag is 16 bytes
     */
    encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): {
        ciphertext: Uint8Array;
        tag: Uint8Array;
    };
    /**
     * Verify and decrypt ciphertext.
     *
     * **Always verifies the Poly1305 tag before decrypting.**
     * Uses constant-time comparison for tag verification — safe against timing attacks.
     *
     * @param key        256-bit key (32 bytes)
     * @param nonce      96-bit nonce (12 bytes) — must match the value used to encrypt
     * @param ciphertext ciphertext to decrypt
     * @param tag        16-byte authentication tag produced by encrypt()
     * @param aad        additional authenticated data (must match value used to encrypt)
     * @returns plaintext on success
     * @throws Error('ChaCha20Poly1305: authentication failed') if tag does not match
     */
    decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Uint8Array;
}
/**
 * AEAD_XChaCha20_Poly1305 per XChaCha20 IETF draft (draft-irtf-cfrg-xchacha-03).
 *
 * Extends ChaCha20-Poly1305 with a 192-bit nonce (vs 96-bit). The larger nonce
 * makes random generation safe — 2^96 messages expected before collision at 50%
 * probability, compared to 2^48 for 96-bit nonces.
 *
 * **Recommended for new applications.** Use ChaCha20Poly1305 only when
 * RFC 8439 interoperability with 96-bit nonces is required.
 *
 * Construction: derive a subkey from key + nonce[0..15] via HChaCha20,
 * then run AEAD_CHACHA20_POLY1305 with subkey + [0x00×4 || nonce[16..23]].
 *
 * Key:   256-bit (32 bytes)
 * Nonce: 192-bit (24 bytes) — safe to generate randomly via crypto.getRandomValues
 */
export declare class XChaCha20Poly1305 {
    private readonly _inner;
    /**
     * Encrypt and authenticate plaintext using XChaCha20-Poly1305.
     *
     * @param key       256-bit key (32 bytes)
     * @param nonce     192-bit nonce (24 bytes). Safe to generate randomly.
     * @param plaintext message to encrypt
     * @param aad       additional authenticated data
     * @returns `{ ciphertext, tag }` — ciphertext.length === plaintext.length, tag is 16 bytes
     */
    encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): {
        ciphertext: Uint8Array;
        tag: Uint8Array;
    };
    /**
     * Verify and decrypt ciphertext using XChaCha20-Poly1305.
     *
     * Always verifies the tag before returning plaintext.
     * Uses constant-time tag comparison.
     *
     * @throws Error('XChaCha20Poly1305: authentication failed') if tag is invalid
     */
    decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Uint8Array;
}
