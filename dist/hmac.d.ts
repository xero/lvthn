import { Hash, KeyedHash } from './base';
/**
 * HMAC class
 */
export declare class HMAC implements KeyedHash {
    private hasher;
    hashSize: number;
    B: number;
    iPad: number;
    oPad: number;
    iKeyPad: Uint8Array;
    oKeyPad: Uint8Array;
    /**
     * ctor
     * @param {Hash} hasher Hashing function
     */
    constructor(hasher: Hash);
    /**
     * Init the HMAC
     * @param {Uint8Array} key The key
     */
    init(key: Uint8Array): HMAC;
    /**
     * Update the HMAC with additional message data
     * @param {Uint8Array} msg Additional message data
     * @return {HMAC} this object
     */
    update(msg?: Uint8Array): HMAC;
    /**
     * Finalize the HMAC with additional message data
     * @param {Uint8Array} msg Additional message data
     * @return {Uint8Array} HMAC (Hash-based Message Authentication Code)
     */
    digest(msg?: Uint8Array): Uint8Array;
    /**
     * All in one step
     * @param {Uint8Array} key Key
     * @param {Uint8Array} msg Message data
     * @return {Uint8Array} Hash as byte array
     */
    hash(key: Uint8Array, msg?: Uint8Array): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
export declare class HMAC_SHA256 extends HMAC {
    constructor();
}
export declare class HMAC_SHA512 extends HMAC {
    constructor();
}
