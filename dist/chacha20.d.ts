import { Streamcipher } from './base';
/**
 * ChaCha20 class
 */
export declare class ChaCha20 implements Streamcipher {
    keySize: number;
    nonceSize: number;
    input: Uint32Array;
    /**
     * ctor
     */
    constructor();
    /**
     * Init, private function
      * @param {Array} key The secret key as byte array (32 byte)
      * @param {Array} nonce The nonce (IV) as byte array (8 byte)
      * @param {Number} counter Optional counter init value, 0 is default
      * @return {ChaCha20} this
     */
    private init;
    private U8TO32_LITTLE;
    private U32TO8_LITTLE;
    private ROTATE;
    private QUARTERROUND;
    private stream;
    /**
     * Encrypt a byte array, native chacha20 function
     * @param {Uint8Array} key The secret key as byte array (32 byte)
     * @param {Uint8Array} pt Plaintext as byte array
     * @param {Uint8Array} iv The nonce (IV) as byte array (8 byte)
     * @param {Number} cnt Optional counter init value, 0 is default
     * @return {Uint8Array} ct Ciphertext as byte array
     */
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array, cnt?: number): Uint8Array;
    /**
     * Decrypt a byte array, native chacha20 function
     * @param {Uint8Array} key The secret key as byte array
     * @param {Uint8Array} ct Ciphertext as byte array
     * @param {Uint8Array} iv The nonce (IV) as byte array
     * @param {Number} cnt Optional counter init value, 0 is default
     * @return {Uint8Array} pt Plaintext as byte array
     */
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array, cnt?: number): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
