import { Blockcipher, Streamcipher } from './base';
import { CBC, CTR } from './blockmode';
import { PKCS7 } from './padding';
/**
 * Optional debug callback invoked after each encryption round.
 * round: round index 0–31
 * state: 5-element working register array r[0..4] (snapshot, not live)
 * ec: the EC/DC constant for this round; use ec%5, ec%7, ec%11, ec%13 to
 *     identify which r[] slots hold X0, X1, X2, X3 respectively.
 */
export type RoundHook = (round: number, state: number[], ec: number) => void;
/**
 * Serpent class
 */
export declare class Serpent implements Blockcipher {
    blockSize: number;
    key: Uint32Array;
    wMax: number;
    /** Optional hook called after every cipher round during encrypt/decrypt. */
    roundHook: RoundHook | null;
    rotW: Function;
    getW: Function;
    setW: Function;
    setWInv: Function;
    keyIt: Function;
    keyLoad: Function;
    keyStore: Function;
    S: Array<Function>;
    SI: Array<Function>;
    /**
     * Serpent ctor
     */
    constructor();
    /**
     * Init the cipher, private function
     * @param {Uint8Array} key The key. The key size can be 128, 192 or 256 bits
     */
    private init;
    private K;
    private LK;
    private KL;
    /**
     * Expose the derived subkeys for testing/verification.
     * Returns a copy of the 132-word subkey array (33 subkeys × 4 words each).
     * this.key[4*i .. 4*i+3] = [X0, X1, X2, X3] of subkey i (i=0..32).
     * Note: ecb_iv.txt SK[] values are printed by render() in REVERSED word order
     * (word[3] first, word[0] last), so SK[i] from file = X3|X2|X1|X0 in hex.
     */
    getSubkeys(key: Uint8Array): Uint32Array;
    /**
     * Serpent block encryption
     * @param {Uint8Array} key Key
     * @param {Uint8Array} pt The plaintext
     * @return {Uint8Array} Ciphertext
     */
    encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array;
    /**
     * Serpent block decryption
     * @param {Uint8Array} key Key
     * @param {Uint8Array} ct The ciphertext
     * @return {Uint8Array} Plaintext
     */
    decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array;
    /**
     * Performs a quick selftest
     * @return {Boolean} True if successful
     */
    selftest(): boolean;
}
export declare class Serpent_CBC implements Streamcipher {
    cipher: Serpent;
    blockmode: CBC;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export declare class Serpent_CTR implements Streamcipher {
    cipher: Serpent;
    blockmode: CTR;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export declare class Serpent_CBC_PKCS7 implements Streamcipher {
    cipher: Serpent_CBC;
    padding: PKCS7;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
export declare class Serpent_CTR_PKCS7 implements Streamcipher {
    cipher: Serpent_CTR;
    padding: PKCS7;
    constructor();
    encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array;
    decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array;
    selftest(): boolean;
}
