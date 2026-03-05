export declare const version = "1.1.4";
export interface Blockcipher {
    blockSize: number;
    encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export interface Streamcipher {
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export interface PublicKey {
    generateKeys(seed: Uint8Array): {
        sk: Uint8Array;
        pk: Uint8Array;
    };
    encrypt(pk: Uint8Array, pt: Uint8Array): Uint8Array;
    decrypt(sk: Uint8Array, ct: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export interface Signature {
    generateKeys(seed: Uint8Array): {
        sk: Uint8Array;
        pk: Uint8Array;
    } | undefined;
    sign(msg: Uint8Array, sk: Uint8Array, pk: Uint8Array): Uint8Array | undefined;
    verify(msg: Uint8Array, pk: Uint8Array, sig: Uint8Array): boolean;
    selftest(): boolean;
}
export interface Hash {
    hashSize: number;
    init(): Hash;
    update(msg?: Uint8Array): Hash;
    digest(msg?: Uint8Array): Uint8Array;
    hash(msg?: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export interface KeyedHash {
    hashSize: number;
    init(key: Uint8Array): KeyedHash;
    update(msg?: Uint8Array): KeyedHash;
    digest(msg?: Uint8Array): Uint8Array;
    hash(key: Uint8Array, msg?: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export declare namespace Convert {
    /**
     * Convert a string (UTF-8 encoded) to a byte array
     * @param {String} str UTF-8 encoded string
     * @return {Uint8Array} Byte array
     */
    function str2bin(str: string): Uint8Array;
    /**
     * Convert a hex string to byte array
     * @param {String} hex Hex string
     * @return {Uint8Array} Byte array
     */
    function hex2bin(hex: string): Uint8Array;
    /**
     * Convert a 32 bit integer number to a 4 byte array, LSB is first
     * @param {Number} integer Integer number
     * @return {Uint8Array} bin 4 byte array
     */
    function int2bin(integer: number): Uint8Array;
    /**
     * Convert a number to a 8 byte array, LSB is first
     * @param {Number} value Long number
     * @return {Uint8Array} bin 8 byte array
     */
    function number2bin(value: number): Uint8Array;
    /**
     * Convert a base64/base64url string to a byte array
     * @param {String} base64 Base64/Base64url encoded string
     * @return {Uint8Array} Byte array or undefined if error
     */
    function base642bin(base64: string): Uint8Array | undefined;
    /**
     * Convert a byte array to hex string
     * @param {Uint8Array} bin The input byte array
     * @param {Boolean} uppercase True for upper case hex numbers
     * @return {String} Hex sting
     */
    function bin2hex(bin: Uint8Array, uppercase?: boolean): string;
    /**
     * Convert a byte array to string (UTF-8 dedode)
     * @param {Uint8Array} bin UTF-8 text given as array of bytes
     * @return {String} UTF-8 Text string
     */
    function bin2str(bin: Uint8Array): string;
    /**
     * Convert a byte value array in a long value array
     * @param {Uint8Array} bin Array of bytes
     * @return {Uint32Array} bin values in long format
     */
    function bin2longbin(bin: Uint8Array): Uint32Array;
    /**
     * Convert a 8 byte (int64) array into a number
     * @param {Uint8Array} bin Array of 8 bytes (int64), LSB is [0], MSB is [7]
     * @return {Number} int64 value as number
     */
    function bin2number(bin: Uint8Array): number;
    /**
     * Convert byte array to base64/base64url string
     * @param {Uint8Array} bin Array of bytes
     * @param {Boolean} url True if the string should be URL encoded (base64url encoding)
     * @return {String} Base64 encoded string
     */
    function bin2base64(bin: Uint8Array, url?: boolean): string;
}
/**
 * Constant-time byte-array equality test.
 *
 * Compares two Uint8Arrays without short-circuiting on the first differing
 * byte.  Ordinary === / Array.every / early-return loops reveal WHERE two
 * values diverge via execution time, enabling byte-at-a-time MAC/HMAC
 * forgery (e.g. Lucky Thirteen, Vaudenay's CBC padding oracle family).
 *
 * The XOR-accumulate idiom (`diff |= a[i] ^ b[i]`) is the standard
 * constant-time pattern: every byte is visited regardless of content, and
 * the result collapses to a single final comparison.
 *
 * Notes:
 *   - The length check is NOT constant-time.  Length is non-secret in all
 *     protocols where this is used (the expected tag length is public).
 *   - Do NOT add timing padding or dummy operations — they are ineffective
 *     in a JIT environment and create false confidence.
 *
 * @param a First byte array
 * @param b Second byte array
 * @returns true if and only if a and b have equal length and identical content
 */
export declare const constantTimeEqual: (a: Uint8Array, b: Uint8Array) => boolean;
export declare namespace Util {
    /**
     * Time constant comparison of two arrays.
     * Delegates to constantTimeEqual — see its JSDoc for the security rationale.
     * @param {Uint8Array} lh First array of bytes
     * @param {Uint8Array} rh Second array of bytes
     * @return {Boolean} True if the arrays are equal (length and content), false otherwise
     */
    function compare(lh: Uint8Array, rh: Uint8Array): boolean;
    /**
     * Clear an array
     * @param {Uint8Array | Uint16Array | Uint32Array} Array to clear
     */
    function clear(data: Uint8Array | Uint16Array | Uint32Array): void;
    /**
     * XOR two arrays and return the result array
     * @param {Uint8Array} lh First array of bytes
     * @param {Uint8Array} rh Second array of bytes
     * @return {Uint8Array} XORed result array
     */
    function xor(lh: Uint8Array, rh: Uint8Array): Uint8Array;
    /**
     * Concat two arrays and returns a new result array
     * @param {Uint8Array} lh First array of bytes
     * @param {Uint8Array} rh Second array of bytes
     * @return {Uint8Array} Concatenated result array
     */
    function concat(lh: Uint8Array, rh: Uint8Array): Uint8Array;
    /**
     * Returns true if LITTLE endian is detected
     * @return {Boolean} True for LE, false for BE
     */
    function litteendian(): boolean;
}
