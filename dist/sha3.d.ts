import { Hash } from './base';
/**
 * Keccak class
 */
export declare class Keccak implements Hash {
    private padding;
    hashSize: number;
    blockCount: number;
    byteCount: number;
    buffer: Uint8Array;
    bufferIndex: number;
    s: Uint32Array;
    RC: Uint32Array;
    /**
     * Keccak ctor
     * @param {Number} bits Capacity
     * @param {Number} padding Padding value, 1 for Keccak, 6 for SHA3 and 31 for SHAKE
     * @param {Number} length Optional length of the output hash in bits. If not given bits is taken as default.
     */
    constructor(bits: number, padding: number, length?: number);
    /**
     * Init the hash
     * @return {Keccak} this
     */
    init(): Keccak;
    /**
     * Update the hash with additional message data
     * @param {Uint8Array} msg Additional message data as byte array
     * @return {Keccak} this
     */
    update(msg?: Uint8Array): Keccak;
    /**
     * Finalize the hash with additional message data
     * @param {Uint8Array} msg Additional message data as byte array
     * @return {Uint8Array} Hash as byte array
     */
    digest(msg?: Uint8Array): Uint8Array;
    /**
     * All in one step
     * @param {Uint8Array} msg Additional message data
     * @return {Uint8Array} Hash as byte array
     */
    hash(msg?: Uint8Array): Uint8Array;
    /**
     * Absorb function
     * @private
     */
    private keccakf;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
/**
 * Keccak-256 class
 */
export declare class Keccak_256 extends Keccak {
    constructor();
}
/**
 * Keccak-384 class
 */
export declare class Keccak_384 extends Keccak {
    constructor();
}
/**
 * SHA3-512 class
 */
export declare class Keccak_512 extends Keccak {
    constructor();
}
/**
 * SHA3-256 class
 */
export declare class SHA3_256 extends Keccak {
    constructor();
}
/**
 * SHA3-384 class
 */
export declare class SHA3_384 extends Keccak {
    constructor();
}
/**
 * SHA3-512 class
 */
export declare class SHA3_512 extends Keccak {
    constructor();
}
/**
 * SHAKE128 class
 */
export declare class SHAKE128 extends Keccak {
    constructor(length: number);
}
/**
 * SHAKE256 class
 */
export declare class SHAKE256 extends Keccak {
    constructor(length: number);
}
