///////////////////////////////////////////////////////////////////////////////
//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          this file is part of the
//        ▄██████████████████████ ▀████▄      leviathan crypto library
//      ▄█████████▀▀▀     ▀███████▄▄███████▌
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  repository
//     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      author: xero (https://x-e.ro)
//       ▀██████   ▄▄██            ▀▀  ██▄    license: mit
//         ▀█████▄   ▄██▄             ▄▀▄▀
//            ▀████▄   ▄██▄                   +---------------+
//              ▐████   ▐███                  |   test spec   |
//       ▄▄██████████    ▐███         ▄▄      +---------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         this file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. the author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// ChaCha20 tests
// Vectors: chacha20_vectors.ts (IETF draft-agl-tls-chacha20poly1305-04 + RFC 7539)
// @see https://datatracker.ietf.org/doc/html/draft-agl-tls-chacha20poly1305-04
// @see https://www.rfc-editor.org/rfc/rfc7539
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { ChaCha20 } from '../../src/chacha20';
import { Convert } from '../../src/base';
import { vector } from '../vectors/chacha20_vectors';

describe('ChaCha20', () => {
  const chacha = new ChaCha20();

  describe('encrypt', () => {
    it(`check ${vector.length} test vectors`, () => {
      for (const v of vector) {
        const pt = typeof v.pt !== 'undefined'
          ? Convert.hex2bin(v.pt)
          : new Uint8Array(v.ct.length / 2);
        const out = chacha.encrypt(Convert.hex2bin(v.key), pt, Convert.hex2bin(v.iv), v.ibc);
        expect(out).toEqual(Convert.hex2bin(v.ct));
      }
    });
  });

  describe('decrypt', () => {
    it(`check ${vector.length} test vectors`, () => {
      for (const v of vector) {
        const pt = typeof v.pt !== 'undefined'
          ? Convert.hex2bin(v.pt)
          : new Uint8Array(v.ct.length / 2);
        const out = chacha.decrypt(Convert.hex2bin(v.key), Convert.hex2bin(v.ct), Convert.hex2bin(v.iv), v.ibc);
        expect(out).toEqual(pt);
      }
    });
  });
});
