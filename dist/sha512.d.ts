import { Hash } from './base';
/**
 * SHA512 class
 */
export declare class SHA512 implements Hash {
    hashSize: number;
    buffer: Uint8Array;
    bufferIndex: number;
    count: Uint32Array;
    K: Uint32Array;
    H: Uint32Array;
    /**
     * SHA512 ctor
     */
    constructor();
    /**
     * Init the hash
     * @return {Object} this
     */
    init(): SHA512;
    /**
     * Perform one transformation cycle
     */
    private transform;
    /**
     * Update the hash with additional message data
     * @param {Uint8Array} msg Additional message data as byte array
     * @return {SHA512} this
     */
    update(msg?: Uint8Array): SHA512;
    /**
     * Finalize the hash with additional message data
     * @param {Uint8Array} msg Additional message data as byte array
     * @return {Uint8Array} Hash as 64 byte array
     */
    digest(msg?: Uint8Array): Uint8Array;
    /**
     * All in one step
     * @param {Uint8Array} msg Additional message data
     * @return {Uint8Array} Hash as 64 byte array
     */
    hash(msg?: Uint8Array): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
