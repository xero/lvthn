///////////////////////////////////////////////////////////////////////////////
//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          This file is part of the
//        ▄██████████████████████ ▀████▄      leviathan crypto library
//      ▄█████████▀▀▀     ▀███████▄▄███████▌
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  Repository
//     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Author: xero (https://x-e.ro)
//       ▀██████   ▄▄██            ▀▀  ██▄    License: MIT
//         ▀█████▄   ▄██▄             ▄▀▄▀
//            ▀████▄   ▄██▄                   +---------------+
//              ▐████   ▐███                  |    PADDING    |
//       ▄▄██████████    ▐███         ▄▄      +---------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// PKCS7 Padding and stripping
///////////////////////////////////////////////////////////////////////////////
export class PKCS7 {
    /**
     * PKCS#7 padding function. Pads bytes to given text until text is multiple of blocksize is met
     * @param {Uint8Array} bin Byte array where the bytes are padded
     * @param {Number} blocksize The blocksize in bytes of the text to which the text should be padded
     * @return {Uint8Array} Padded byte array
     */
    pad(bin, blocksize) {
        let len = bin.length % blocksize ? blocksize - (bin.length % blocksize) : blocksize;
        let out = new Uint8Array(bin.length + len);
        out.set(bin, 0);
        for (let i = bin.length, l = bin.length + len; i < l; ++i) {
            out[i] = len;
        }
        return out;
    }
    /**
     * PKCS#7 stripping function. Strips bytes of the given text
     * @param {Uint8Array} bin Byte array where the bytes are stripped
     * @return {Uint8Array} Stripped byte array
     */
    strip(bin) {
        return bin.subarray(0, bin.length - bin[bin.length - 1]);
    }
}
