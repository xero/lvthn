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
// Base utility tests (Convert, Util)
//
// Note: the original "explicit no atob/btoa" tests tried to null globals to
// exercise the internal fallback path. In Node 18+ globalThis.atob/btoa are
// non-configurable, so that technique no longer works. The tests are kept but
// without the unreliable global manipulation — the conversion correctness is
// what matters.
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { Convert, Util } from '../../src/base';

// ---------------------------------------------------------------------------
// Base64 test vectors (plaintext → base64)
// ---------------------------------------------------------------------------
const base64Vector: [string, string][] = [
  ['', ''],
  ['f', 'Zg=='],
  ['fo', 'Zm8='],
  ['foo', 'Zm9v'],
  ['foob', 'Zm9vYg=='],
  ['fooba', 'Zm9vYmE='],
  ['foobar', 'Zm9vYmFy'],
  ['1234567890', 'MTIzNDU2Nzg5MA=='],
  ['sQrs8KCz8r9o9kggoaUdQkY', 'c1FyczhLQ3o4cjlvOWtnZ29hVWRRa1k='],
  ['1234567890abcdefghijklmnopqrstuvwxyz', 'MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6'],
];

// ---------------------------------------------------------------------------
// Convert
// ---------------------------------------------------------------------------

describe('Convert', () => {

  describe('hex2bin', () => {
    it('hex to bin for all lengths 0–255', () => {
      for (let strlen = 0; strlen < 256; strlen++) {
        const exp = new Uint8Array(strlen);
        let inp = '';
        for (let i = 0; i < strlen; i++) {
          inp += (i < 16 ? '0' : '') + i.toString(16);
          exp[i] = i;
        }
        expect(Convert.hex2bin(inp)).toEqual(exp);
      }
    });
  });

  describe('bin2hex', () => {
    it('bin to hex (lowercase and uppercase) for all lengths 0–255', () => {
      for (let strlen = 0; strlen < 256; strlen++) {
        const inp = new Uint8Array(strlen);
        let expL = '';
        let expU = '';
        for (let i = 0; i < strlen; i++) {
          expL += (i < 16 ? '0' : '') + i.toString(16).toLowerCase();
          expU += (i < 16 ? '0' : '') + i.toString(16).toUpperCase();
          inp[i] = i;
        }
        expect(Convert.bin2hex(inp)).toEqual(expL);
        expect(Convert.bin2hex(inp, true)).toEqual(expU);
      }
    });
  });

  describe('base642bin', () => {
    it('base64 vectors decode correctly', () => {
      for (const [pt, ct] of base64Vector) {
        expect(Convert.base642bin(ct)).toEqual(Convert.str2bin(pt));
      }
    });
  });

  describe('bin2base64', () => {
    it('base64 vectors encode correctly', () => {
      for (const [pt, ct] of base64Vector) {
        expect(Convert.bin2base64(Convert.str2bin(pt))).toEqual(ct);
      }
    });
  });

  describe('bin2base64 → base642bin round-trip (standard)', () => {
    it('round-trip for random arrays 0–299 bytes', () => {
      for (let i = 0; i < 300; i++) {
        const bin = new Uint8Array(i);
        for (let n = 0; n < i; n++) bin[n] = Math.floor(Math.random() * 0xff);
        expect(Convert.base642bin(Convert.bin2base64(bin))).toEqual(bin);
      }
    });
  });

  describe('bin2base64 → base642bin round-trip (URL-safe)', () => {
    it('round-trip for random arrays 0–299 bytes (base64url)', () => {
      for (let i = 0; i < 300; i++) {
        const bin = new Uint8Array(i);
        for (let n = 0; n < i; n++) bin[n] = Math.floor(Math.random() * 0xff);
        expect(Convert.base642bin(Convert.bin2base64(bin, true))).toEqual(bin);
      }
    });
  });

});

// ---------------------------------------------------------------------------
// Util
// ---------------------------------------------------------------------------

describe('Util', () => {

  describe('clear', () => {
    it('sets all elements to 0', () => {
      const bin = new Uint8Array(300);
      for (let n = 0; n < 300; n++) bin[n] = Math.floor(Math.random() * 0xff);
      Util.clear(bin);
      expect(bin).toEqual(new Uint8Array(300));
    });
  });

  describe('compare', () => {
    it('equal arrays return true, different arrays or lengths return false', () => {
      const ar1 = new Uint8Array(300);
      for (let n = 0; n < 300; n++) ar1[n] = Math.floor(Math.random() * 0xff);
      const ar2 = ar1.slice();
      expect(Util.compare(ar1, ar2)).toBe(true);
      ar1[100] ^= 1;
      expect(Util.compare(ar1, ar2)).toBe(false);
      const ar3 = ar1.slice(0, 299);
      expect(Util.compare(ar1, ar3)).toBe(false);
    });
  });

  describe('xor', () => {
    it('XORs two arrays element-wise', () => {
      const bin1 = new Uint8Array(300);
      const bin2 = new Uint8Array(300);
      for (let n = 0; n < 300; n++) {
        bin1[n] = Math.floor(Math.random() * 0xff);
        bin2[n] = Math.floor(Math.random() * 0xff);
      }
      const xor1 = Util.xor(bin1, bin2);
      const xor2 = new Uint8Array(300);
      for (let n = 0; n < 300; n++) xor2[n] = bin1[n] ^ bin2[n];
      expect(xor1).toEqual(xor2);
    });
  });

});
