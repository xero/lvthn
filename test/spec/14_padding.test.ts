////////////////////////////////////////////////////////////////////////////////
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
//            ▀████▄   ▄██▄                   +-----------------+
//              ▐████   ▐███                  |   block modes   |
//       ▄▄██████████    ▐███         ▄▄      +-----------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// PKCS7 Padding tests
////////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { PKCS7 } from '../../src/padding';

describe('Padding', () => {
  const padding = new PKCS7();

  describe('PKCS7', () => {
    it('pad and strip round-trip for all block sizes and lengths', () => {
      for (let bs = 2; bs < 32; bs += 2) {
        for (let len = 0; len < 128; len++) {
          const bin = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            bin[i] = Math.floor(Math.random() * 256);
          }
          const bin2 = new Uint8Array(bin);
          const b2 = padding.pad(bin, bs);
          expect(b2.length % bs).toBe(0);
          const b3 = padding.strip(b2);
          expect(b3).toEqual(bin2);
        }
      }
    });
  });
});
