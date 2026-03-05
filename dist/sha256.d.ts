import { Hash } from './base';
/**
 * SHA256 class
 */
export declare class SHA256 implements Hash {
    hashSize: number;
    buffer: Uint8Array;
    bufferIndex: number;
    count: Uint32Array;
    K: Uint32Array;
    H: Uint32Array;
    /**
     * SHA256 ctor
     */
    constructor();
    /**
     * Init the hash
     * @return {SHA256} this
     */
    init(): SHA256;
    /**
     * Perform one transformation cycle
     */
    private transform;
    /**
     * Update the hash with additional message data
     * @param {Array} msg Additional message data as byte array
     * @return {SHA256} this
     */
    update(msg?: Uint8Array): SHA256;
    /**
     * Finalize the hash with additional message data
     * @param {Uint8Array} msg Additional message data as byte array
     * @return {Uint8Array} Hash as 32 byte array
     */
    digest(msg?: Uint8Array): Uint8Array;
    /**
     * All in one step
     * @param {Uint8Array} msg Message data as byte array
     * @return {Uint8Array} Hash as 32 byte array
     */
    hash(msg?: Uint8Array): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
