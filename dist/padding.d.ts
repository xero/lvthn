export declare class PKCS7 {
    /**
   * PKCS#7 padding function. Pads bytes to given text until text is multiple of blocksize is met
   * @param {Uint8Array} bin Byte array where the bytes are padded
   * @param {Number} blocksize The blocksize in bytes of the text to which the text should be padded
   * @return {Uint8Array} Padded byte array
   */
    pad(bin: Uint8Array, blocksize: number): Uint8Array;
    /**
   * PKCS#7 stripping function. Strips bytes of the given text
   * @param {Uint8Array} bin Byte array where the bytes are stripped
   * @return {Uint8Array} Stripped byte array
   */
    strip(bin: Uint8Array): Uint8Array;
}
