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
// CBC Monte Carlo Tests — cbc_e_m.txt and cbc_d_m.txt
//
// Inner loop algorithm (from cbc_e_m.c):
//
// ENCRYPT inner loop (j=0..9999):
//   CV = current IV
//   CT = E(key, PT XOR IV)    [one CBC block]
//   PT_next = CV              (next PT = previous IV, not CT!)
//   IV_next = CT              (CBC mode: IV updated to CT)
//   record CT_9998 at j=9998
//
// After inner loop:
//   next PT  = CT_9998
//   next IV  = CT_9999
//   next KEY = KEY XOR suffix(CT_9998 || CT_9999)
//
// DECRYPT inner loop (from cbc_d_m.c):
//   CV = current IV
//   PT = D(key, CT) XOR IV    [one CBC block]
//   IV_next = CT              (CBC: IV = previous ciphertext)
//   CT_next = PT              (next ciphertext = this plaintext)
//   record PT_9998 at j=9998
//
// §floppy1/cbc_e_m.c, §floppy1/cbc_d_m.c
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect, beforeAll } from 'vitest';
import { Serpent } from '../../src/serpent';
import {
  readVector, hex2bytes, bytes2hex, padKey, xorBlocks,
  parseMcCbcEncrypt, parseMcCbcDecrypt,
  McCbcVector,
} from '../helpers/vectors';

const INNER_LOOP = 10000;

// ─────────────────────────────────────────────────────────────────────────────
// Inner loop helpers
// ─────────────────────────────────────────────────────────────────────────────

function runCbcEncryptInnerLoop(
  serpent: Serpent,
  key: Uint8Array,
  initIV: Uint8Array,
  initPt: Uint8Array
): { ct9998: Uint8Array; ct9999: Uint8Array } {
  let iv = new Uint8Array(initIV);
  let pt = new Uint8Array(initPt);
  let ct9998 = new Uint8Array(16);
  let ct9999 = new Uint8Array(16);

  for (let j = 0; j < INNER_LOOP; j++) {
    const cv = new Uint8Array(iv);       // save current IV = CV_j
    const ib = xorBlocks(pt, iv);        // IB_j = PT_j XOR IV_j
    const ct = serpent.encrypt(key, ib); // CT_j = E(key, IB_j)
    if (j === INNER_LOOP - 2) ct9998 = new Uint8Array(ct);
    ct9999 = ct;
    pt = cv;  // PT_{j+1} = CV_j  (not CT!)
    iv = ct;  // IV_{j+1} = CT_j
  }
  return { ct9998, ct9999 };
}

function runCbcDecryptInnerLoop(
  serpent: Serpent,
  key: Uint8Array,
  initIV: Uint8Array,
  initCt: Uint8Array
): { pt9998: Uint8Array; pt9999: Uint8Array } {
  let iv = new Uint8Array(initIV);
  let ct = new Uint8Array(initCt);
  let pt9998 = new Uint8Array(16);
  let pt9999 = new Uint8Array(16);

  for (let j = 0; j < INNER_LOOP; j++) {
    const decrypted = serpent.decrypt(key, ct); // D(key, CT_j)
    const pt = xorBlocks(decrypted, iv);        // PT_j = D(key, CT_j) XOR IV_j
    if (j === INNER_LOOP - 2) pt9998 = new Uint8Array(pt);
    pt9999 = pt;
    iv = ct;  // IV_{j+1} = CT_j
    ct = pt;  // CT_{j+1} = PT_j (feedback: use decrypted as next ciphertext)
  }
  return { pt9998, pt9999 };
}

function mcKeyUpdate(keysize: number, currentKey: Uint8Array, prev9998: Uint8Array, prev9999: Uint8Array): Uint8Array {
  const concat = new Uint8Array(32);
  concat.set(prev9998, 0);
  concat.set(prev9999, 16);
  const keyBytes = keysize / 8;
  const suffix = concat.slice(32 - keyBytes);
  const newKey = new Uint8Array(keyBytes);
  for (let i = 0; i < keyBytes; i++) newKey[i] = currentKey[i] ^ suffix[i];
  return newKey;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test data
// ─────────────────────────────────────────────────────────────────────────────

let cbcEmVectors: McCbcVector[];
let cbcDmVectors: McCbcVector[];

beforeAll(() => {
  cbcEmVectors = parseMcCbcEncrypt(readVector('cbc_e_m.txt'));
  cbcDmVectors = parseMcCbcDecrypt(readVector('cbc_d_m.txt'));
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. CBC Monte Carlo Encrypt
// ─────────────────────────────────────────────────────────────────────────────

describe('AES Monte Carlo CBC: cbc_e_m.txt', () => {
  it('parses non-zero vectors', () => {
    expect(cbcEmVectors.length).toBeGreaterThan(0);
  });

  it('all vectors pass (10000-iteration inner loop)', () => {
    const s = new Serpent();
    for (const v of cbcEmVectors) {
      const key = padKey(v.key, v.keysize);
      const iv  = hex2bytes(v.iv);
      const pt  = hex2bytes(v.pt);
      const { ct9999 } = runCbcEncryptInnerLoop(s, key, iv, pt);
      expect(bytes2hex(ct9999)).toEqual(v.ct);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. CBC Monte Carlo Decrypt
// ─────────────────────────────────────────────────────────────────────────────

describe('AES Monte Carlo CBC: cbc_d_m.txt', () => {
  it('parses non-zero vectors', () => {
    expect(cbcDmVectors.length).toBeGreaterThan(0);
  });

  it('all vectors pass (10000-iteration inner loop)', () => {
    const s = new Serpent();
    for (const v of cbcDmVectors) {
      const key = padKey(v.key, v.keysize);
      const iv  = hex2bytes(v.iv);
      const ct  = hex2bytes(v.ct);
      const { pt9999 } = runCbcDecryptInnerLoop(s, key, iv, ct);
      expect(bytes2hex(pt9999)).toEqual(v.pt);
    }
  });
});
