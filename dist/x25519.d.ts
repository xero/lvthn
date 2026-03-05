import { Signature } from './base';
import { SHA512 } from './sha512';
/**
 * Curve25519 class
 */
export declare class Curve25519 {
    gf0: Int32Array;
    gf1: Int32Array;
    D: Int32Array;
    D2: Int32Array;
    I: Int32Array;
    _9: Uint8Array;
    _121665: Int32Array;
    /**
     * Curve25519 ctor
     */
    constructor();
    gf(init?: Array<number>): Int32Array;
    private A;
    private Z;
    M(o: Int32Array, a: Int32Array, b: Int32Array): void;
    private S;
    add(p: Array<Int32Array>, q: Array<Int32Array>): void;
    set25519(r: Int32Array, a: Int32Array): void;
    private car25519;
    private sel25519;
    inv25519(o: Int32Array, i: Int32Array): void;
    private neq25519;
    par25519(a: Int32Array): number;
    private pow2523;
    cswap(p: Array<Int32Array>, q: Array<Int32Array>, b: number): void;
    pack25519(o: Uint8Array, n: Int32Array): void;
    private unpack25519;
    unpackNeg(r: Array<Int32Array>, p: Uint8Array): number;
    /**
     * Internal scalar mult function
     * @param q Result
     * @param s Secret key
     * @param p Public key
     */
    private crypto_scalarmult;
    /**
     * Generate the common key as the produkt of sk1 * pk2
     * @param {Uint8Array} sk A 32 byte secret key of pair 1
     * @param {Uint8Array} pk A 32 byte public key of pair 2
     * @return {Uint8Array} sk * pk
     */
    scalarMult(sk: Uint8Array, pk: Uint8Array): Uint8Array;
    /**
     * Generate a curve 25519 keypair
     * @param {Uint8Array} seed A 32 byte cryptographic secure random array. This is basically the secret key
     * @param {Object} Returns sk (Secret key) and pk (Public key) as 32 byte typed arrays
     */
    generateKeys(seed: Uint8Array): {
        sk: Uint8Array;
        pk: Uint8Array;
    } | undefined;
    /**
     * Performs a quick selftest
     * @param {Boolean} Returns true if selftest passed
     */
    selftest(): boolean;
}
/**
 * Ed25519 class
 */
export declare class Ed25519 implements Signature {
    curve: Curve25519;
    sha512: SHA512;
    X: Int32Array;
    Y: Int32Array;
    L: Uint8Array;
    /**
     * Ed25519 ctor
     */
    constructor();
    private pack;
    private modL;
    private reduce;
    private scalarmult;
    private scalarbase;
    /**
     * Generate an ed25519 keypair
     * Some implementations represent the secret key as a combination of sk and pk. leviathan just uses the sk itself.
     * @param {Uint8Array} seed A 32 byte cryptographic secure random array. This is basically the secret key
     * @param {Object} Returns sk (Secret key) and pk (Public key) as 32 byte typed arrays
     */
    generateKeys(seed: Uint8Array): {
        sk: Uint8Array;
        pk: Uint8Array;
    } | undefined;
    /**
     * Generate a message signature
     * @param {Uint8Array} msg Message to be signed as byte array
     * @param {Uint8Array} sk Secret key as 32 byte array
     * @param {Uint8Array} pk Public key as 32 byte array
     * @param {Uint8Array} Returns the signature as 64 byte typed array
     */
    sign(msg: Uint8Array, sk: Uint8Array, pk: Uint8Array): Uint8Array | undefined;
    /**
     * Verify a message signature
     * @param {Uint8Array} msg Message to be signed as byte array
     * @param {Uint8Array} pk Public key as 32 byte array
     * @param {Uint8Array} sig Signature as 64 byte array
     * @param {Boolean} Returns true if signature is valid
     */
    verify(msg: Uint8Array, pk: Uint8Array, sig: Uint8Array): boolean;
    /**
     * Performs a quick selftest
     * @param {Boolean} Returns true if selftest passed
     */
    selftest(): boolean;
}
