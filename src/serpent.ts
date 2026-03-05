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
//            ▀████▄   ▄██▄                   +-------------------+
//              ▐████   ▐███                  |    SERPENT 256    |
//       ▄▄██████████    ▐███         ▄▄      +-------------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// Serpent256 is a symmetric block cipher algorithm with a 128-bit block size
// that supports 128, 192, or 256-bit key sizes. The cipher employs a 32-round
// substitution–permutation network operating on a block of four 32-bit words.
// Each round applies one of eight 4-bit to 4-bit S-boxes 32 times in parallel.
// Its bit slicing technique maximizes parallelism and allows utilization of
// the extensive cryptanalysis work performed on DES. This implementation
// adheres to the format of the original AES submission and has been fully
// tested against all vectors provided by the authors.
// Specification can befound here: http://www.cl.cam.ac.uk/~rja14/serpent.html
//
///////////////////////////////////////////////////////////////////////////////

import { Convert, Util, Blockcipher, Streamcipher } from './base';
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
export class Serpent implements Blockcipher {
  blockSize: number;
  key!: Uint32Array;
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
  constructor() {
    this.blockSize = 16; // Serpent has a fixed block size of 16 bytes (4x4)
    this.wMax = 0xffffffff;
    this.roundHook = null;

    this.rotW = function (w: number, n: number) {
      return (w << n | w >>> (32 - n)) & this.wMax;
    };

    this.getW = function (a: Uint8Array, i: number) {
      return a[i] | a[i + 1] << 8 | a[i + 2] << 16 | a[i + 3] << 24;
    };

    this.setW = function (a: Uint8Array, i: number, w: number) {
      a[i] = w & 0xff; a[i + 1] = (w >>> 8) & 0xff; a[i + 2] = (w >>> 16) & 0xff; a[i + 3] = (w >>> 24) & 0xff;
    };

    this.setWInv = function (a: Uint8Array, i: number, w: number) {
      a[i] = (w >>> 24) & 0xff; a[i + 1] = (w >>> 16) & 0xff; a[i + 2] = (w >>> 8) & 0xff; a[i + 3] = w & 0xff;
    };

    this.keyIt = function (a: number, b: number, c: number, d: number, i: number, r: number[]) {
      this.key[i] = r[b] = this.rotW(this.key[a] ^ r[b] ^ r[c] ^ r[d] ^ 0x9e3779b9 ^ i, 11);
    };

    this.keyLoad = function (a: number, b: number, c: number, d: number, i: number, r: number[]) {
      r[a] = this.key[i]; r[b] = this.key[i + 1]; r[c] = this.key[i + 2]; r[d] = this.key[i + 3];
    };

    this.keyStore = function (a: number, b: number, c: number, d: number, i: number, r: number[]) {
      this.key[i] = r[a]; this.key[i + 1] = r[b]; this.key[i + 2] = r[c]; this.key[i + 3] = r[d];
    };

    this.S = [
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x3] |= r[x0]; r[x0] ^= r[x4]; r[x4] ^= r[x2]; r[x4] = ~r[x4]; r[x3] ^= r[x1];
        r[x1] &= r[x0]; r[x1] ^= r[x4]; r[x2] ^= r[x0]; r[x0] ^= r[x3]; r[x4] |= r[x0]; r[x0] ^= r[x2];
        r[x2] &= r[x1]; r[x3] ^= r[x2]; r[x1] = ~r[x1]; r[x2] ^= r[x4]; r[x1] ^= r[x2];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x1] ^= r[x0]; r[x0] ^= r[x3]; r[x3] = ~r[x3]; r[x4] &= r[x1]; r[x0] |= r[x1];
        r[x3] ^= r[x2]; r[x0] ^= r[x3]; r[x1] ^= r[x3]; r[x3] ^= r[x4]; r[x1] |= r[x4]; r[x4] ^= r[x2];
        r[x2] &= r[x0]; r[x2] ^= r[x1]; r[x1] |= r[x0]; r[x0] = ~r[x0]; r[x0] ^= r[x2]; r[x4] ^= r[x1];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x3] = ~r[x3]; r[x1] ^= r[x0]; r[x4]  = r[x0]; r[x0] &= r[x2]; r[x0] ^= r[x3]; r[x3] |= r[x4];
        r[x2] ^= r[x1]; r[x3] ^= r[x1]; r[x1] &= r[x0]; r[x0] ^= r[x2]; r[x2] &= r[x3]; r[x3] |= r[x1];
        r[x0] = ~r[x0]; r[x3] ^= r[x0]; r[x4] ^= r[x0]; r[x0] ^= r[x2]; r[x1] |= r[x2];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x1] ^= r[x3]; r[x3] |= r[x0]; r[x4] &= r[x0]; r[x0] ^= r[x2]; r[x2] ^= r[x1]; r[x1] &= r[x3];
        r[x2] ^= r[x3]; r[x0] |= r[x4]; r[x4] ^= r[x3]; r[x1] ^= r[x0]; r[x0] &= r[x3]; r[x3] &= r[x4];
        r[x3] ^= r[x2]; r[x4] |= r[x1]; r[x2] &= r[x1]; r[x4] ^= r[x3]; r[x0] ^= r[x3]; r[x3] ^= r[x2];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x3] &= r[x0]; r[x0] ^= r[x4]; r[x3] ^= r[x2]; r[x2] |= r[x4]; r[x0] ^= r[x1];
        r[x4] ^= r[x3]; r[x2] |= r[x0]; r[x2] ^= r[x1]; r[x1] &= r[x0]; r[x1] ^= r[x4]; r[x4] &= r[x2];
        r[x2] ^= r[x3]; r[x4] ^= r[x0]; r[x3] |= r[x1]; r[x1] = ~r[x1]; r[x3] ^= r[x0];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x1] |= r[x0]; r[x2] ^= r[x1]; r[x3] = ~r[x3]; r[x4] ^= r[x0]; r[x0] ^= r[x2];
        r[x1] &= r[x4]; r[x4] |= r[x3]; r[x4] ^= r[x0]; r[x0] &= r[x3]; r[x1] ^= r[x3]; r[x3] ^= r[x2];
        r[x0] ^= r[x1]; r[x2] &= r[x4]; r[x1] ^= r[x2]; r[x2] &= r[x0]; r[x3] ^= r[x2];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x1]; r[x3] ^= r[x0]; r[x1] ^= r[x2]; r[x2] ^= r[x0]; r[x0] &= r[x3]; r[x1] |= r[x3];
        r[x4] = ~r[x4]; r[x0] ^= r[x1]; r[x1] ^= r[x2]; r[x3] ^= r[x4]; r[x4] ^= r[x0]; r[x2] &= r[x0];
        r[x4] ^= r[x1]; r[x2] ^= r[x3]; r[x3] &= r[x1]; r[x3] ^= r[x0]; r[x1] ^= r[x2];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x1] = ~r[x1]; r[x4]  = r[x1]; r[x0] = ~r[x0]; r[x1] &= r[x2]; r[x1] ^= r[x3]; r[x3] |= r[x4]; r[x4] ^= r[x2];
        r[x2] ^= r[x3]; r[x3] ^= r[x0]; r[x0] |= r[x1]; r[x2] &= r[x0]; r[x0] ^= r[x4]; r[x4] ^= r[x3];
        r[x3] &= r[x0]; r[x4] ^= r[x1]; r[x2] ^= r[x4]; r[x3] ^= r[x1]; r[x4] |= r[x0]; r[x4] ^= r[x1];
      }
    ];

    this.SI = [
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x1] ^= r[x0]; r[x3] |= r[x1]; r[x4] ^= r[x1]; r[x0] = ~r[x0]; r[x2] ^= r[x3];
        r[x3] ^= r[x0]; r[x0] &= r[x1]; r[x0] ^= r[x2]; r[x2] &= r[x3]; r[x3] ^= r[x4]; r[x2] ^= r[x3];
        r[x1] ^= r[x3]; r[x3] &= r[x0]; r[x1] ^= r[x0]; r[x0] ^= r[x2]; r[x4] ^= r[x3];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x1] ^= r[x3]; r[x4]  = r[x0]; r[x0] ^= r[x2]; r[x2] = ~r[x2]; r[x4] |= r[x1]; r[x4] ^= r[x3];
        r[x3] &= r[x1]; r[x1] ^= r[x2]; r[x2] &= r[x4]; r[x4] ^= r[x1]; r[x1] |= r[x3]; r[x3] ^= r[x0];
        r[x2] ^= r[x0]; r[x0] |= r[x4]; r[x2] ^= r[x4]; r[x1] ^= r[x0]; r[x4] ^= r[x1];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x2] ^= r[x1]; r[x4]  = r[x3]; r[x3] = ~r[x3]; r[x3] |= r[x2]; r[x2] ^= r[x4]; r[x4] ^= r[x0];
        r[x3] ^= r[x1]; r[x1] |= r[x2]; r[x2] ^= r[x0]; r[x1] ^= r[x4]; r[x4] |= r[x3]; r[x2] ^= r[x3];
        r[x4] ^= r[x2]; r[x2] &= r[x1]; r[x2] ^= r[x3]; r[x3] ^= r[x4]; r[x4] ^= r[x0];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x2] ^= r[x1]; r[x4]  = r[x1]; r[x1] &= r[x2]; r[x1] ^= r[x0]; r[x0] |= r[x4]; r[x4] ^= r[x3];
        r[x0] ^= r[x3]; r[x3] |= r[x1]; r[x1] ^= r[x2]; r[x1] ^= r[x3]; r[x0] ^= r[x2]; r[x2] ^= r[x3];
        r[x3] &= r[x1]; r[x1] ^= r[x0]; r[x0] &= r[x2]; r[x4] ^= r[x3]; r[x3] ^= r[x0]; r[x0] ^= r[x1];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x2] ^= r[x3]; r[x4]  = r[x0]; r[x0] &= r[x1]; r[x0] ^= r[x2]; r[x2] |= r[x3]; r[x4] = ~r[x4];
        r[x1] ^= r[x0]; r[x0] ^= r[x2]; r[x2] &= r[x4]; r[x2] ^= r[x0]; r[x0] |= r[x4]; r[x0] ^= r[x3];
        r[x3] &= r[x2]; r[x4] ^= r[x3]; r[x3] ^= r[x1]; r[x1] &= r[x0]; r[x4] ^= r[x1]; r[x0] ^= r[x3];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  =  r[x1]; r[x1] |= r[x2]; r[x2] ^= r[x4]; r[x1] ^= r[x3]; r[x3] &= r[x4]; r[x2] ^= r[x3]; r[x3] |= r[x0];
        r[x0]  = ~r[x0]; r[x3] ^= r[x2]; r[x2] |= r[x0]; r[x4] ^= r[x1]; r[x2] ^= r[x4]; r[x4] &= r[x0]; r[x0] ^= r[x1];
        r[x1] ^=  r[x3]; r[x0] &= r[x2]; r[x2] ^= r[x3]; r[x0] ^= r[x2]; r[x2] ^= r[x4]; r[x4] ^= r[x3];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x0] ^= r[x2]; r[x4]  = r[x0]; r[x0] &= r[x3]; r[x2] ^= r[x3]; r[x0] ^= r[x2]; r[x3] ^= r[x1];
        r[x2] |= r[x4]; r[x2] ^= r[x3]; r[x3] &= r[x0]; r[x0] = ~r[x0]; r[x3] ^= r[x1]; r[x1] &= r[x2];
        r[x4] ^= r[x0]; r[x3] ^= r[x4]; r[x4] ^= r[x2]; r[x0] ^= r[x1]; r[x2] ^= r[x0];
      },
      function (r: number[], x0: number, x1: number, x2: number, x3: number, x4: number) {
        r[x4]  = r[x3]; r[x3] &= r[x0]; r[x0] ^= r[x2]; r[x2] |= r[x4]; r[x4] ^= r[x1]; r[x0] = ~r[x0]; r[x1] |= r[x3];
        r[x4] ^= r[x0]; r[x0] &= r[x2]; r[x0] ^= r[x1]; r[x1] &= r[x2]; r[x3] ^= r[x2]; r[x4] ^= r[x3];
        r[x2] &= r[x3]; r[x3] |= r[x0]; r[x1] ^= r[x4]; r[x3] ^= r[x4]; r[x4] &= r[x0]; r[x4] ^= r[x2];
      }
    ];
  }


  /**
   * Init the cipher, private function
   * @param {Uint8Array} key The key. The key size can be 128, 192 or 256 bits
   */
  private init(key: Uint8Array) {
    let i, j, m, n, len;
    const KC = new Uint32Array([7788, 63716, 84032, 7891, 78949, 25146, 28835, 67288, 84032, 40055, 7361, 1940, 77639, 27525, 24193, 75702,
                                7361, 35413, 83150, 82383, 58619, 48468, 18242, 66861, 83150, 69667, 7788, 31552, 40054, 23222, 52496, 57565, 7788, 63716]);

    this.key = new Uint32Array(132);
    this.key[key.length] = 1;
    // reverse
    for (i = 0, len = key.length; i < len; i++) {
      this.key[i] = key[len - i - 1];
    }

    for (i = 0; i < 8; i++) {
      this.key[i] = (this.key[4 * i] & 0xff) | (this.key[4 * i + 1] & 0xff) << 8 | (this.key[4 * i + 2] & 0xff) << 16 | (this.key[4 * i + 3] & 0xff) << 24;
    }

    let r = [this.key[3], this.key[4], this.key[5], this.key[6], this.key[7]];

    i = 0; j = 0;
    while (this.keyIt(j++, 0, 4, 2, i++, r), this.keyIt(j++, 1, 0, 3, i++, r), i < 132) {
      this.keyIt(j++, 2, 1, 4, i++, r);
      if (i === 8) {
        j = 0;
      }
      this.keyIt(j++, 3, 2, 0, i++, r);
      this.keyIt(j++, 4, 3, 1, i++, r);
    }

    i = 128; j = 3; n = 0;
    while (m = KC[n++], this.S[j++ % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17), m = KC[n], this.keyStore(m % 5, m % 7, m % 11, m % 13, i, r), i > 0) {
      i -= 4;
      this.keyLoad(m % 5, m % 7, m % 11, m % 13, i, r);
    }
  }


  private K(r: number[], a: number, b: number, c: number, d: number, i: number) {
    r[a] ^= this.key[4 * i];
    r[b] ^= this.key[4 * i + 1];
    r[c] ^= this.key[4 * i + 2];
    r[d] ^= this.key[4 * i + 3];
  }


  private LK(r: number[], a: number, b: number, c: number, d: number, e: number, i: number) {
    r[a]  = this.rotW(r[a], 13);
    r[c]  = this.rotW(r[c], 3);
    r[b] ^= r[a];
    r[e]  = (r[a] << 3) & this.wMax;
    r[d] ^= r[c];
    r[b] ^= r[c];
    r[b]  = this.rotW(r[b], 1);
    r[d] ^= r[e];
    r[d]  = this.rotW(r[d], 7);
    r[e]  = r[b];
    r[a] ^= r[b];
    r[e]  = (r[e] << 7) & this.wMax;
    r[c] ^= r[d];
    r[a] ^= r[d];
    r[c] ^= r[e];
    r[d] ^= this.key[4 * i + 3];
    r[b] ^= this.key[4 * i + 1];
    r[a]  = this.rotW(r[a], 5);
    r[c]  = this.rotW(r[c], 22);
    r[a] ^= this.key[4 * i + 0];
    r[c] ^= this.key[4 * i + 2];
  }


  private KL(r: number[], a: number, b: number, c: number, d: number, e: number, i: number) {
    r[a] ^= this.key[4 * i + 0];
    r[b] ^= this.key[4 * i + 1];
    r[c] ^= this.key[4 * i + 2];
    r[d] ^= this.key[4 * i + 3];
    r[a]  = this.rotW(r[a], 27);
    r[c]  = this.rotW(r[c], 10);
    r[e]  = r[b];
    r[c] ^= r[d];
    r[a] ^= r[d];
    r[e]  = (r[e] << 7) & this.wMax;
    r[a] ^= r[b];
    r[b]  = this.rotW(r[b], 31);
    r[c] ^= r[e];
    r[d]  = this.rotW(r[d], 25);
    r[e]  = (r[a] << 3) & this.wMax;
    r[b] ^= r[a];
    r[d] ^= r[e];
    r[a]  = this.rotW(r[a], 19);
    r[b] ^= r[c];
    r[d] ^= r[c];
    r[c]  = this.rotW(r[c], 29);
  }


  /**
   * Expose the derived subkeys for testing/verification.
   * Returns a copy of the 132-word subkey array (33 subkeys × 4 words each).
   * this.key[4*i .. 4*i+3] = [X0, X1, X2, X3] of subkey i (i=0..32).
   * Note: ecb_iv.txt SK[] values are printed by render() in REVERSED word order
   * (word[3] first, word[0] last), so SK[i] from file = X3|X2|X1|X0 in hex.
   */
  getSubkeys(key: Uint8Array): Uint32Array {
    this.init(key);
    return new Uint32Array(this.key);
  }

  /**
   * Serpent block encryption
   * @param {Uint8Array} key Key
   * @param {Uint8Array} pt The plaintext
   * @return {Uint8Array} Ciphertext
   */
  encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array {
    this.init(key);

    const EC = new Uint32Array([44255, 61867, 45034, 52496, 73087, 56255, 43827, 41448, 18242, 1939, 18581, 56255, 64584, 31097, 26469,
                                77728, 77639, 4216, 64585, 31097, 66861, 78949, 58006, 59943, 49676, 78950, 5512, 78949, 27525, 52496, 18670, 76143]);

    let blk = new Uint8Array(pt.length);
    // reverse
    for (let i = 0, len = pt.length; i < len; i++) {
      blk[i] = pt[len - i - 1];
    }
    let r = [this.getW(blk, 0), this.getW(blk, 4), this.getW(blk, 8), this.getW(blk, 12)];

    this.K(r, 0, 1, 2, 3, 0);
    let n = 0, m = EC[0];
    while (this.S[n % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17), n < 31) {
      m = EC[++n];
      this.LK(r, m % 5, m % 7, m % 11, m % 13, m % 17, n);
      // §debug-hook: called after round (n-1) completes (after LT + subkey XOR)
      // X0=r[m%5], X1=r[m%7], X2=r[m%11], X3=r[m%13] for ec=m
      if (this.roundHook) { this.roundHook(n - 1, r.slice(), m); }
    }
    // Round 31: S-box applied above (loop exit), XOR final subkey K32
    // EC[31]=76143: X0=r[3], X1=r[4], X2=r[1], X3=r[2] before K(32)
    // After K(32) with hardcoded indices (0,1,2,3), the assignment shifts:
    // r[0]=temp^key128, r[1]=X2^key129, r[2]=X3^key130, r[3]=X0^key131
    this.K(r, 0, 1, 2, 3, 32);
    // Report round 31 post-K32 using EC[31] so hook caller can decode slots
    if (this.roundHook) { this.roundHook(31, r.slice(), EC[31]); }

    let ct = new Uint8Array(pt.length);
    this.setWInv(ct, 0, r[3]); this.setWInv(ct, 4, r[2]); this.setWInv(ct, 8, r[1]); this.setWInv(ct, 12, r[0]);

    return ct;
  }


  /**
   * Serpent block decryption
   * @param {Uint8Array} key Key
   * @param {Uint8Array} ct The ciphertext
   * @return {Uint8Array} Plaintext
   */
  decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array {
    this.init(key);

    const DC = new Uint32Array([44255, 60896, 28835, 1837, 1057, 4216, 18242, 77301, 47399, 53992, 1939, 1940, 66420, 39172, 78950,
                                45917, 82383, 7450, 67288, 26469, 83149, 57565, 66419, 47400, 58006, 44254, 18581, 18228, 33048, 45034, 66508, 7449]);

    let blk = new Uint8Array(ct.length);
    // reverse
    for (let i = 0, len = ct.length; i < len; i++) {
      blk[i] = ct[len - i - 1];
    }
    let r = [this.getW(blk, 0), this.getW(blk, 4), this.getW(blk, 8), this.getW(blk, 12)];

    this.K(r, 0, 1, 2, 3, 32);
    let n = 0, m = DC[0];
    while (this.SI[7 - n % 8](r, m % 5, m % 7, m % 11, m % 13, m % 17), n < 31) {
      m = DC[++n];
      this.KL(r, m % 5, m % 7, m % 11, m % 13, m % 17, 32 - n);
      if (this.roundHook) { this.roundHook(32 - n, r.slice(), m); }
    }
    this.K(r, 2, 3, 1, 4, 0);
    if (this.roundHook) { this.roundHook(0, r.slice(), DC[31]); }

    let pt = new Uint8Array(ct.length);
    this.setWInv(pt, 0, r[4]); this.setWInv(pt, 4, r[1]); this.setWInv(pt, 8, r[3]); this.setWInv(pt, 12, r[2]);

    return pt;
  }


  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    // AES submission KAT: 128-bit all-zero key, variable plaintext (ecb_vt.txt I=1)
    // Verified against the original AES candidate submission by Ross Anderson.
    const key128 = Convert.hex2bin('00000000000000000000000000000000');
    const pt128  = Convert.hex2bin('80000000000000000000000000000000');
    const ct128  = Convert.hex2bin('10b5ffb720b8cb9002a1142b0ba2e94a');
    const s = new Serpent();
    const enc = s.encrypt(key128, pt128);
    const dec = s.decrypt(key128, ct128);
    return Util.compare(enc, ct128) && Util.compare(dec, pt128);
  }

}

///////////////////////////////////////////////////////////////////////////////


export class Serpent_CBC implements Streamcipher {
  cipher: Serpent;
  blockmode: CBC;

  constructor() {
    this.cipher    = new Serpent();
    this.blockmode = new CBC(this.cipher);
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.encrypt(key, pt, iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.decrypt(key, ct, iv);
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}


export class Serpent_CTR implements Streamcipher {
  cipher: Serpent;
  blockmode: CTR;

  constructor() {
    this.cipher    = new Serpent();
    this.blockmode = new CTR(this.cipher);
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.encrypt(key, pt, iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.blockmode.decrypt(key, ct, iv);
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}


export class Serpent_CBC_PKCS7 implements Streamcipher {
  cipher: Serpent_CBC;
  padding: PKCS7;

  constructor() {
    this.cipher  = new Serpent_CBC();
    this.padding = new PKCS7();
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.cipher.encrypt(key, this.padding.pad(pt, this.cipher.cipher.blockSize), iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.padding.strip(this.cipher.decrypt(key, ct, iv));
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}


export class Serpent_CTR_PKCS7 implements Streamcipher {
  cipher: Serpent_CTR;
  padding: PKCS7;

  constructor() {
    this.cipher  = new Serpent_CTR();
    this.padding = new PKCS7();
  }

  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.cipher.encrypt(key, this.padding.pad(pt, this.cipher.cipher.blockSize), iv);
  }

  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    return this.padding.strip(this.cipher.decrypt(key, ct, iv));
  }

  selftest(): boolean {
    return this.cipher.selftest();
  }
}
