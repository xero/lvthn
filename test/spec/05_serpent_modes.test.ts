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
// Serpent block mode wrapper tests
// Tests Serpent_CBC, Serpent_CTR, Serpent_CBC_PKCS7, Serpent_CTR_PKCS7
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { Serpent_CBC, Serpent_CTR, Serpent_CBC_PKCS7, Serpent_CTR_PKCS7 } from '../../src/serpent';
import { Convert } from '../../src/base';

// 128-bit all-zero key and all-zero IV reused across tests
const key128  = new Uint8Array(16);
const key256  = new Uint8Array(32);
const iv0     = new Uint8Array(16);

describe('Serpent_CBC', () => {
  // Instantiate fresh for each group to avoid counter-state cross-contamination.
  const cbc = new Serpent_CBC();

  it('selftest passes', () => {
    expect(cbc.selftest()).toBe(true);
  });

  it('known vector: IV=0 reduces first block to ECB (ecb_vt.txt, KEYSIZE=128, I=1)', () => {
    // CBC_encrypt(key, pt, iv=0): block_0 = Serpent_ECB(key, pt XOR 0) = Serpent_ECB(key, pt)
    // Same vector used in serpent.ts selftest().
    const pt = Convert.hex2bin('80000000000000000000000000000000');
    const ct = cbc.encrypt(key128, pt, iv0);
    expect(Convert.bin2hex(ct)).toBe('10b5ffb720b8cb9002a1142b0ba2e94a');
  });

  it('round-trip: 128-bit key, single block', () => {
    const pt = new Uint8Array(16).fill(0xab);
    const iv = new Uint8Array(16); iv[0] = 0x01;
    const ct  = cbc.encrypt(key128, pt, iv);
    const dec = cbc.decrypt(key128, ct, iv);
    expect(dec).toEqual(pt);
  });

  it('round-trip: 256-bit key, two blocks', () => {
    const pt = new Uint8Array(32);
    for (let i = 0; i < 32; i++) pt[i] = i;
    const iv = new Uint8Array(16); iv[15] = 0x07;
    const ct  = cbc.encrypt(key256, pt, iv);
    const dec = cbc.decrypt(key256, ct, iv);
    expect(dec).toEqual(pt);
  });

  it('different IVs produce different ciphertexts for the same PT', () => {
    const pt  = new Uint8Array(16).fill(0x55);
    const iv1 = new Uint8Array(16); iv1[0] = 0x01;
    const iv2 = new Uint8Array(16); iv2[0] = 0x02;
    const ct1 = cbc.encrypt(key128, pt, iv1);
    const ct2 = cbc.encrypt(key128, pt, iv2);
    expect(Convert.bin2hex(ct1)).not.toBe(Convert.bin2hex(ct2));
  });
});

///////////////////////////////////////////////////////////////////////////////

describe('Serpent_CTR', () => {
  const ctr = new Serpent_CTR();

  it('selftest passes', () => {
    expect(ctr.selftest()).toBe(true);
  });

  it('round-trip: 128-bit key, single block', () => {
    const pt  = new Uint8Array(16).fill(0x37);
    const ct  = ctr.encrypt(key128, pt, iv0);
    const dec = ctr.decrypt(key128, ct, iv0);
    expect(dec).toEqual(pt);
  });

  it('round-trip: 256-bit key, three blocks', () => {
    const pt = new Uint8Array(48);
    for (let i = 0; i < 48; i++) pt[i] = i;
    const iv = new Uint8Array(16); iv[0] = 0xde; iv[1] = 0xad;
    const ct  = ctr.encrypt(key256, pt, iv);
    const dec = ctr.decrypt(key256, ct, iv);
    expect(dec).toEqual(pt);
  });

  it('CTR is a symmetric XOR stream cipher: encrypt(PT) == decrypt(PT)', () => {
    // Both encrypt and decrypt XOR against the same keystream, so they are identical ops.
    const pt  = new Uint8Array(16).fill(0xcd);
    const iv  = new Uint8Array(16); iv[7] = 0xff;
    const ct  = ctr.encrypt(key128, pt, iv);
    const ct2 = ctr.decrypt(key128, pt, iv);
    expect(ct).toEqual(ct2);
  });

  it('different IVs produce different ciphertexts', () => {
    const pt  = new Uint8Array(16).fill(0x99);
    const iv1 = new Uint8Array(16); iv1[0] = 0x01;
    const iv2 = new Uint8Array(16); iv2[0] = 0x02;
    const ct1 = ctr.encrypt(key128, pt, iv1);
    const ct2 = ctr.encrypt(key128, pt, iv2);
    expect(Convert.bin2hex(ct1)).not.toBe(Convert.bin2hex(ct2));
  });
});

///////////////////////////////////////////////////////////////////////////////

describe('Serpent_CBC_PKCS7', () => {
  const cbc7 = new Serpent_CBC_PKCS7();

  it('round-trip: block-aligned PT — PKCS7 appends a full padding block', () => {
    const pt = new Uint8Array(16).fill(0x55);
    const ct  = cbc7.encrypt(key256, pt, iv0);
    expect(ct.length).toBe(32);   // PKCS7 always adds at least one byte
    const dec = cbc7.decrypt(key256, ct, iv0);
    expect(dec).toEqual(pt);
  });

  it('round-trip: 13-byte PT — padded to one full block', () => {
    const pt = new Uint8Array(13);
    for (let i = 0; i < 13; i++) pt[i] = i * 7;
    const iv = new Uint8Array(16); iv[0] = 0xca; iv[1] = 0xfe;
    const ct  = cbc7.encrypt(key256, pt, iv);
    expect(ct.length).toBe(16);   // 13 + 3 bytes of padding = 16
    const dec = cbc7.decrypt(key256, ct, iv);
    expect(dec).toEqual(pt);
  });

  it('round-trip: 256-bit key, two-block plaintext', () => {
    const pt = new Uint8Array(32);
    for (let i = 0; i < 32; i++) pt[i] = 255 - i;
    const iv = new Uint8Array(16); iv[8] = 0x42;
    const ct  = cbc7.encrypt(key256, pt, iv);
    const dec = cbc7.decrypt(key256, ct, iv);
    expect(dec).toEqual(pt);
  });
});

///////////////////////////////////////////////////////////////////////////////

describe('Serpent_CTR_PKCS7', () => {
  const ctr7 = new Serpent_CTR_PKCS7();

  it('round-trip: block-aligned PT', () => {
    const pt = new Uint8Array(32).fill(0x77);
    const ct  = ctr7.encrypt(key256, pt, iv0);
    const dec = ctr7.decrypt(key256, ct, iv0);
    expect(dec).toEqual(pt);
  });

  it('round-trip: 23-byte PT — padded to two blocks', () => {
    const pt = new Uint8Array(23);
    for (let i = 0; i < 23; i++) pt[i] = 255 - i;
    const iv = new Uint8Array(16); iv[15] = 0x07;
    const ct  = ctr7.encrypt(key256, pt, iv);
    expect(ct.length).toBe(32);   // 23 + 9 bytes of padding = 32
    const dec = ctr7.decrypt(key256, ct, iv);
    expect(dec).toEqual(pt);
  });

  it('round-trip: 128-bit key, single block', () => {
    const pt = new Uint8Array(7);
    for (let i = 0; i < 7; i++) pt[i] = i * 13;
    const iv = new Uint8Array(16); iv[0] = 0xbe; iv[1] = 0xef;
    const ct  = ctr7.encrypt(key128, pt, iv);
    const dec = ctr7.decrypt(key128, ct, iv);
    expect(dec).toEqual(pt);
  });
});
