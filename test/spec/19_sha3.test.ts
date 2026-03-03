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
// sha-3 / keccak / shake tests
// vectors: sha3_256/512 and shake128/256 vector files (nist fips 202 — partial)
// @see https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { Keccak_384, SHA3_256, SHA3_512, SHAKE128, SHAKE256 } from '../../src/sha3';
import { Convert } from '../../src/base';
import { sha3_256_vector } from '../vectors/sha3_256_vectors';
import { sha3_512_vector } from '../vectors/sha3_512_vectors';
import { shake128_vector } from '../vectors/shake128_vectors';
import { shake256_vector } from '../vectors/shake256_vectors';
import { shake128_vector_long } from '../vectors/shake128_vectors_long';
import { shake256_vector_long } from '../vectors/shake256_vectors_long';

// suppress unused-import warnings — the long vectors are imported for future use
void shake128_vector_long;
void shake256_vector_long;

describe('Keccak-384', () => {
  const sha = new Keccak_384();

  describe('hash', () => {
    it('hash of "Message" matches expected', () => {
      const pt = 'Message';
      const ct = '0c8d6ff6e6a1cf18a0d55b20f0bca160d0d1c914a5e842f3707a25eeb20a279f6b4e83eda8e43a67697832c7f69f53ca';
      expect(Convert.bin2hex(sha.hash(Convert.str2bin(pt)))).toEqual(ct);
    });
  });
});


describe('SHA3-256', () => {
  const sha = new SHA3_256();

  describe('hash', () => {
    it(`check ${sha3_256_vector.length} test vectors (one-shot)`, () => {
      for (const [pt, ct] of sha3_256_vector) {
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).toEqual(ct);
      }
    });
  });

  describe('update', () => {
    it(`check ${sha3_256_vector.length} test vectors (byte-by-byte update)`, () => {
      for (const [pt, ct] of sha3_256_vector) {
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).toEqual(ct);
      }
    });
  });

  describe('selftest', () => {
    it('selftest passes', () => {
      expect(sha.selftest()).toBe(true);
    });
  });
});


describe('SHA3-512', () => {
  const sha = new SHA3_512();

  describe('hash', () => {
    it(`check ${sha3_512_vector.length} test vectors (one-shot)`, () => {
      for (const [pt, ct] of sha3_512_vector) {
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).toEqual(ct);
      }
    });
  });

  describe('update', () => {
    it(`check ${sha3_512_vector.length} test vectors (byte-by-byte update)`, () => {
      for (const [pt, ct] of sha3_512_vector) {
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).toEqual(ct);
      }
    });
  });
});


describe('SHAKE128-256', () => {
  const sha = new SHAKE128(256);

  describe('hash', () => {
    it(`check ${shake128_vector.length} test vectors (one-shot)`, () => {
      for (const [pt, ct] of shake128_vector) {
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).toEqual(ct);
      }
    });
  });

  describe('update', () => {
    it(`check ${shake128_vector.length} test vectors (byte-by-byte update)`, () => {
      for (const [pt, ct] of shake128_vector) {
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).toEqual(ct);
      }
    });
  });
});


describe('SHAKE256-512', () => {
  const sha = new SHAKE256(512);

  describe('hash', () => {
    it(`check ${shake256_vector.length} test vectors (one-shot)`, () => {
      for (const [pt, ct] of shake256_vector) {
        expect(Convert.bin2hex(sha.hash(Convert.hex2bin(pt)), true)).toEqual(ct);
      }
    });
  });

  describe('update', () => {
    it(`check ${shake256_vector.length} test vectors (byte-by-byte update)`, () => {
      for (const [pt, ct] of shake256_vector) {
        sha.init();
        for (let j = 0; j < pt.length; j += 2) {
          sha.update(Convert.hex2bin(pt.substr(j, 2)));
        }
        expect(Convert.bin2hex(sha.digest(), true)).toEqual(ct);
      }
    });
  });
});
