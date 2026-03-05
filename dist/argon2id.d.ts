/**
 * Argon2id tuning parameters.
 *
 * Use one of the named presets ({@link ARGON2ID_INTERACTIVE},
 * {@link ARGON2ID_SENSITIVE}, {@link ARGON2ID_DERIVE}) rather than
 * constructing raw parameter objects, unless you have benchmarked Argon2id
 * on your target hardware for a specific time budget.
 */
export interface Argon2idParams {
    /** RAM allocated per hash attempt in kibibytes (KiB). Higher = stronger against GPU/ASIC. */
    memoryCost: number;
    /** Number of passes over memory. Higher = slower per attempt. */
    timeCost: number;
    /** Degree of parallelism (lanes / threads). */
    parallelism: number;
    /** Salt length in bytes. Minimum 8; OWASP recommends 32. */
    saltLength: number;
    /** Output hash/key length in bytes. Minimum 4. */
    hashLength: number;
}
/**
 * Result returned by {@link Argon2id.hash}.
 *
 * Store all three fields together — they are all required to verify a
 * password or re-derive a key later. Losing the salt or params makes the
 * hash permanently unverifiable.
 */
export interface Argon2idResult {
    /** Raw Argon2id hash output. */
    hash: Uint8Array;
    /** Salt used (caller-provided or auto-generated). */
    salt: Uint8Array;
    /** Parameters used — required for later verification or re-derivation. */
    params: Argon2idParams;
}
/**
 * OWASP 2023 minimum recommendation — suitable for most interactive logins.
 *
 * 19 MiB RAM, 2 passes, 1 thread. Typically 50–200 ms on modern server
 * hardware. Use this for login/registration flows where response latency
 * matters.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export declare const ARGON2ID_INTERACTIVE: Argon2idParams;
/**
 * OWASP 2023 high-security profile — for sensitive credentials where slower
 * is acceptable.
 *
 * 64 MiB RAM, 3 passes, 4 threads. Expect 200 ms–1 s on server hardware.
 * Use for high-value accounts, passphrase-protected secrets, or key escrow.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export declare const ARGON2ID_SENSITIVE: Argon2idParams;
/**
 * Key derivation preset — INTERACTIVE parameters optimised for deriving
 * Serpent encryption keys from passphrases.
 *
 * Always outputs 32 bytes (256-bit), directly usable as a Serpent-256 key.
 * Store the returned salt alongside the ciphertext — it is required to
 * re-derive the same key for decryption.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export declare const ARGON2ID_DERIVE: Argon2idParams;
/**
 * Argon2id — memory-hard password hashing and key derivation.
 *
 * Argon2id is the winner of the Password Hashing Competition (2015) and is
 * standardised in RFC 9106 (2021). It is the recommended replacement for
 * the deprecated {@link PBKDF2}.
 *
 * Unlike PBKDF2, which is purely CPU-bound, Argon2id forces each password
 * guess to allocate and fill a large RAM buffer. This makes brute-force
 * attacks with GPUs or ASICs orders of magnitude more expensive than
 * CPU-only KDFs.
 *
 * Argon2id combines Argon2d (data-dependent memory access, GPU-resistant)
 * with Argon2i (data-independent memory access, side-channel-resistant),
 * making it the correct choice for both password storage and key derivation.
 *
 * @example Password hashing and verification
 * ```typescript
 * const argon2 = new Argon2id();
 * const { hash, salt, params } = await argon2.hash('correct horse battery staple');
 * // store hash + salt + params ...
 * const ok = await argon2.verify('correct horse battery staple', hash, salt, params);
 * ```
 *
 * @example Key derivation for Serpent encryption
 * ```typescript
 * const { key, salt } = await new Argon2id().deriveKey('my passphrase');
 * // store salt alongside ciphertext for decryption
 * const cipher = new Serpent_CBC_PKCS7();
 * const ciphertext = cipher.encrypt(key, plaintext, iv);
 * ```
 */
export declare class Argon2id {
    /**
     * Hash a password or derive a key from a passphrase.
     *
     * Generates a random salt via `crypto.getRandomValues` if none is provided.
     * The global `crypto` object is available in Node.js 19+, Bun, and all
     * modern browsers.
     *
     * **Security:** always store the returned `salt` and `params` alongside the
     * `hash`. All three are required for later verification or re-derivation.
     * Losing the salt makes the hash permanently unverifiable.
     *
     * @param password - plaintext password or passphrase (string or Uint8Array)
     * @param salt     - optional salt; randomly generated if omitted
     * @param params   - Argon2id parameters (default: ARGON2ID_INTERACTIVE)
     * @returns hash, the salt used, and the parameters used
     */
    hash(password: string | Uint8Array, salt?: Uint8Array, params?: Argon2idParams): Promise<Argon2idResult>;
    /**
     * Verify a password against a previously computed hash.
     *
     * Recomputes the hash with the provided salt and params, then compares
     * the result using `constantTimeEqual` — a constant-time XOR-accumulate
     * comparison that always visits every byte regardless of content. This
     * prevents timing oracle attacks that could distinguish correct from
     * incorrect bytes.
     *
     * **Never** use `===`, `Buffer.equals()`, or `Array.every()` to compare
     * Argon2id hashes — they are not constant-time.
     *
     * @param password - plaintext password to verify
     * @param hash     - previously computed hash (from {@link Argon2idResult.hash})
     * @param salt     - salt used when the hash was computed
     * @param params   - parameters used when the hash was computed
     * @returns true if password matches, false otherwise
     */
    verify(password: string | Uint8Array, hash: Uint8Array, salt: Uint8Array, params?: Argon2idParams): Promise<boolean>;
    /**
     * Derive a fixed-length encryption key from a passphrase.
     *
     * Convenience wrapper around {@link hash} using {@link ARGON2ID_DERIVE}
     * parameters. The returned key is directly usable as a Serpent-256 key.
     *
     * **Security:** store the returned `salt` alongside the ciphertext — it
     * is required to re-derive the same key for decryption. The salt is not
     * secret but must be unique per encryption.
     *
     * @param passphrase - source passphrase (string or Uint8Array)
     * @param salt       - optional salt; randomly generated if omitted
     * @param keyLength  - output key length in bytes: 16, 24, or 32 (default: 32)
     * @returns { key, salt } — always store the salt alongside the ciphertext
     */
    deriveKey(passphrase: string | Uint8Array, salt?: Uint8Array, keyLength?: 16 | 24 | 32): Promise<{
        key: Uint8Array;
        salt: Uint8Array;
    }>;
}
