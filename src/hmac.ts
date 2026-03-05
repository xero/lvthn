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
//            ▀████▄   ▄██▄                   +------------+
//              ▐████   ▐███                  |    HMAC    |
//       ▄▄██████████    ▐███         ▄▄      +------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// HMAC keyed hash generator implementation
///////////////////////////////////////////////////////////////////////////////

import { Util, Hash, KeyedHash } from './base';
import { SHA256 } from './sha256';
import { SHA512 } from './sha512';


/**
 * HMAC class
 */
export class HMAC implements KeyedHash {
  hashSize: number;
  B: number;
  iPad: number;
  oPad: number;
  iKeyPad!: Uint8Array;
  oKeyPad!: Uint8Array;


  /**
   * ctor
   * @param {Hash} hasher Hashing function
   */
  constructor(private hasher: Hash) {
    this.hashSize = hasher.hashSize;
    this.B = this.hashSize <= 32 ? 64 : 128;   // according to RFC4868
    this.iPad = 0x36;
    this.oPad = 0x5c;
  }


  /**
   * Init the HMAC
   * @param {Uint8Array} key The key
   */
  init(key: Uint8Array): HMAC {
    // process the key
    let _key = new Uint8Array(key);
    if (_key.length > this.B) {
      // keys longer than blocksize are shortened
      this.hasher.init();
      _key = this.hasher.digest(key);
    }
    // Zero-pad key to block size (inlined from ZeroPadding.pad)
    if (_key.length < this.B) {
      const padded = new Uint8Array(this.B);
      padded.set(_key, 0);
      _key = padded;
    }

    // setup the key pads
    this.iKeyPad = new Uint8Array(this.B);
    this.oKeyPad = new Uint8Array(this.B);
    for (var i = 0; i < this.B; ++i) {
      this.iKeyPad[i] = this.iPad ^ _key[i];
      this.oKeyPad[i] = this.oPad ^ _key[i];
    }

    // security: delete the key
    Util.clear(_key);

    // initial hash
    this.hasher.init();
    this.hasher.update(this.iKeyPad);
    return this;
  }


  /**
   * Update the HMAC with additional message data
   * @param {Uint8Array} msg Additional message data
   * @return {HMAC} this object
   */
  update(msg?: Uint8Array): HMAC {
    msg = msg || new Uint8Array(0);
    this.hasher.update(msg);
    return this;
  }


  /**
   * Finalize the HMAC with additional message data
   * @param {Uint8Array} msg Additional message data
   * @return {Uint8Array} HMAC (Hash-based Message Authentication Code)
   */
  digest(msg?: Uint8Array): Uint8Array {
    msg = msg || new Uint8Array(0);
    let sum1 = this.hasher.digest(msg);   // get sum 1
    this.hasher.init();
    return this.hasher.update(this.oKeyPad).digest(sum1);
  }


  /**
   * All in one step
   * @param {Uint8Array} key Key
   * @param {Uint8Array} msg Message data
   * @return {Uint8Array} Hash as byte array
   */
  hash(key: Uint8Array, msg?: Uint8Array): Uint8Array {
    return this.init(key).digest(msg);
  }


  /**
   * Performs a quick selftest
   * @return {Boolean} True if successful
   */
  selftest(): boolean {
    return false;
  }
}

///////////////////////////////////////////////////////////////////////////////

export class HMAC_SHA256 extends HMAC {
  constructor() {
    super(new SHA256());
  }
}


export class HMAC_SHA512 extends HMAC {
  constructor() {
    super(new SHA512());
  }
}
