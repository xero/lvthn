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
// Tests for ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD
//
// RFC 8439 test vectors (from chacha20poly1305_vectors.ts) are the
// correctness oracle for the underlying primitives.
// @see https://www.rfc-editor.org/rfc/rfc7539
//
// Internal helpers are tested via underscore-prefixed exports from
// blockmode.ts (not re-exported from index.ts — test-only).
///////////////////////////////////////////////////////////////////////////////

import { describe, it, expect } from 'vitest';
import { ChaCha20Poly1305, XChaCha20Poly1305 } from '../../src/index';
import {
  _chacha20Block,
  _poly1305Mac,
  _poly1305KeyGen,
  _hchacha20,
} from '../../src/blockmode';
import {
  chacha20BlockVectors,
  poly1305Vectors,
  poly1305KeyGenVectors,
  hchacha20Vectors,
  chacha20Poly1305Vectors,
  xchacha20Poly1305Vectors,
} from '../vectors/chacha20poly1305_vectors';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/[\s:]/g, '');
  const arr = new Uint8Array(clean.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

function toHex(arr: Uint8Array): string {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// RFC 8439 §A.2 — ChaCha20 block function
// ---------------------------------------------------------------------------

describe('RFC 8439 §A.2 — ChaCha20 block function', () => {

  it(`check ${chacha20BlockVectors.length} RFC vectors`, () => {
    for (const v of chacha20BlockVectors) {
      const key    = fromHex(v.key);
      const nonce  = fromHex(v.nonce);
      const output = _chacha20Block(key, v.counter, nonce);
      expect(toHex(output), v.description).toBe(v.keystream);
    }
  });

  it('returns exactly 64 bytes', () => {
    const key   = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    expect(_chacha20Block(key, 0, nonce)).toHaveLength(64);
  });

  it('different counters produce different keystream blocks', () => {
    const key   = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    const b0 = _chacha20Block(key, 0, nonce);
    const b1 = _chacha20Block(key, 1, nonce);
    expect(toHex(b0)).not.toBe(toHex(b1));
  });

});

// ---------------------------------------------------------------------------
// RFC 8439 §A.3 — Poly1305 MAC
// ---------------------------------------------------------------------------

describe('RFC 8439 §A.3 — Poly1305 MAC', () => {

  it(`check ${poly1305Vectors.length} RFC vectors`, () => {
    for (const v of poly1305Vectors) {
      const key = fromHex(v.key);
      const msg = v.msgText !== undefined
        ? new TextEncoder().encode(v.msgText)
        : fromHex(v.msg!);
      const tag = _poly1305Mac(key, msg);
      expect(toHex(tag), v.description).toBe(v.tag);
    }
  });

  it('Jabberwocky text is exactly 127 bytes', () => {
    const v   = poly1305Vectors.find(v => v.msgText !== undefined)!;
    const msg = new TextEncoder().encode(v.msgText);
    expect(msg.length).toBe(127);
  });

  it('returns exactly 16 bytes regardless of message length', () => {
    const key = new Uint8Array(32);
    for (const len of [0, 1, 15, 16, 17, 63, 64, 65, 200]) {
      expect(_poly1305Mac(key, new Uint8Array(len))).toHaveLength(16);
    }
  });

  it('is deterministic: same key + message → same tag', () => {
    const key = fromHex(poly1305Vectors[1].key);
    const msg = new Uint8Array([1, 2, 3, 4, 5]);
    expect(toHex(_poly1305Mac(key, msg))).toBe(toHex(_poly1305Mac(key, msg)));
    // NOTE: Poly1305 is a one-time MAC — the determinism seen here exists
    // because both calls use the same (key, msg). In the AEAD construction
    // the Poly1305 key is derived fresh via ChaCha20 at counter=0, ensuring
    // the one-time property is maintained across messages.
  });

  it('different messages → different tags (same key)', () => {
    const key = fromHex(poly1305Vectors[1].key);
    expect(toHex(_poly1305Mac(key, new Uint8Array([1, 2, 3]))))
      .not.toBe(toHex(_poly1305Mac(key, new Uint8Array([1, 2, 4]))));
  });

});

// ---------------------------------------------------------------------------
// RFC 8439 §A.4 — Poly1305 key generation
// ---------------------------------------------------------------------------

describe('RFC 8439 §A.4 — Poly1305 key generation', () => {

  it(`check ${poly1305KeyGenVectors.length} RFC vectors`, () => {
    for (const v of poly1305KeyGenVectors) {
      const key   = fromHex(v.key);
      const nonce = fromHex(v.nonce);
      const poly1305Key = _poly1305KeyGen(key, nonce);
      expect(toHex(poly1305Key), v.description).toBe(v.poly1305Key);
    }
  });

  it('returns exactly 32 bytes', () => {
    expect(_poly1305KeyGen(new Uint8Array(32), new Uint8Array(12))).toHaveLength(32);
  });

  it('different nonces → different Poly1305 keys', () => {
    const key    = new Uint8Array(32);
    const nonce1 = new Uint8Array(12);
    const nonce2 = new Uint8Array(12);
    nonce2[0] = 1;
    expect(toHex(_poly1305KeyGen(key, nonce1))).not.toBe(toHex(_poly1305KeyGen(key, nonce2)));
  });

});

// ---------------------------------------------------------------------------
// HChaCha20 — XChaCha20 IETF draft §2.2.1
// ---------------------------------------------------------------------------

describe('HChaCha20 — XChaCha20 IETF draft §2.2.1', () => {

  it(`check ${hchacha20Vectors.length} draft vectors`, () => {
    for (const v of hchacha20Vectors) {
      const key     = fromHex(v.key);
      const nonce16 = fromHex(v.nonce16);
      const subkey  = _hchacha20(key, nonce16);
      expect(toHex(subkey), v.description).toBe(v.subkey);
    }
  });

  it('returns exactly 32 bytes', () => {
    expect(_hchacha20(new Uint8Array(32), new Uint8Array(16))).toHaveLength(32);
  });

  it('different nonce prefixes produce different subkeys', () => {
    const key = new Uint8Array(32);
    const n1  = new Uint8Array(16);
    const n2  = new Uint8Array(16);
    n2[0] = 1;
    expect(toHex(_hchacha20(key, n1))).not.toBe(toHex(_hchacha20(key, n2)));
  });

  it('same key + nonce16 → same subkey (deterministic)', () => {
    const key  = new Uint8Array(32);
    const n16  = fromHex('000000090000004a0000000031415927');
    expect(toHex(_hchacha20(key, n16))).toBe(toHex(_hchacha20(key, n16)));
  });

});

// ---------------------------------------------------------------------------
// AEAD_CHACHA20_POLY1305 — RFC 8439 vectors
// ---------------------------------------------------------------------------

describe('AEAD_CHACHA20_POLY1305 — RFC 8439 vectors', () => {
  const aead = new ChaCha20Poly1305();

  it(`check ${chacha20Poly1305Vectors.length} RFC vectors: tag`, () => {
    for (const v of chacha20Poly1305Vectors) {
      const key       = fromHex(v.key);
      const nonce     = fromHex(v.nonce);
      const aad       = fromHex(v.aad);
      const plaintext = v.ptText !== undefined
        ? new TextEncoder().encode(v.ptText)
        : fromHex(v.pt!);
      const { tag } = aead.encrypt(key, nonce, plaintext, aad);
      expect(toHex(tag), v.description).toBe(v.tag);
    }
  });

  it(`check ${chacha20Poly1305Vectors.length} RFC vectors: ciphertext`, () => {
    for (const v of chacha20Poly1305Vectors) {
      const key       = fromHex(v.key);
      const nonce     = fromHex(v.nonce);
      const aad       = fromHex(v.aad);
      const plaintext = v.ptText !== undefined
        ? new TextEncoder().encode(v.ptText)
        : fromHex(v.pt!);
      const { ciphertext } = aead.encrypt(key, nonce, plaintext, aad);
      expect(toHex(ciphertext), v.description).toBe(v.ct);
    }
  });

  it(`check ${chacha20Poly1305Vectors.length} RFC vectors: decrypt round-trip`, () => {
    for (const v of chacha20Poly1305Vectors) {
      const key       = fromHex(v.key);
      const nonce     = fromHex(v.nonce);
      const aad       = fromHex(v.aad);
      const plaintext = v.ptText !== undefined
        ? new TextEncoder().encode(v.ptText)
        : fromHex(v.pt!);
      const { ciphertext, tag } = aead.encrypt(key, nonce, plaintext, aad);
      const recovered = aead.decrypt(key, nonce, ciphertext, tag, aad);
      expect(toHex(recovered), v.description).toBe(toHex(plaintext));
    }
  });

});

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 — XChaCha20 draft Appendix A.1
// ---------------------------------------------------------------------------

describe('XChaCha20-Poly1305 — XChaCha20 draft Appendix A.1', () => {
  const aead = new XChaCha20Poly1305();

  it(`check ${xchacha20Poly1305Vectors.length} draft vectors: tag`, () => {
    for (const v of xchacha20Poly1305Vectors) {
      const key       = fromHex(v.key);
      const nonce     = fromHex(v.nonce);
      const aad       = fromHex(v.aad);
      const plaintext = v.ptText !== undefined
        ? new TextEncoder().encode(v.ptText)
        : fromHex(v.pt!);
      const { tag } = aead.encrypt(key, nonce, plaintext, aad);
      expect(toHex(tag), v.description).toBe(v.tag);
    }
  });

  it(`check ${xchacha20Poly1305Vectors.length} draft vectors: ciphertext`, () => {
    for (const v of xchacha20Poly1305Vectors) {
      const key       = fromHex(v.key);
      const nonce     = fromHex(v.nonce);
      const aad       = fromHex(v.aad);
      const plaintext = v.ptText !== undefined
        ? new TextEncoder().encode(v.ptText)
        : fromHex(v.pt!);
      const { ciphertext } = aead.encrypt(key, nonce, plaintext, aad);
      expect(toHex(ciphertext), v.description).toBe(v.ct);
    }
  });

  it(`check ${xchacha20Poly1305Vectors.length} draft vectors: decrypt round-trip`, () => {
    for (const v of xchacha20Poly1305Vectors) {
      const key       = fromHex(v.key);
      const nonce     = fromHex(v.nonce);
      const aad       = fromHex(v.aad);
      const plaintext = v.ptText !== undefined
        ? new TextEncoder().encode(v.ptText)
        : fromHex(v.pt!);
      const { ciphertext, tag } = aead.encrypt(key, nonce, plaintext, aad);
      const recovered = aead.decrypt(key, nonce, ciphertext, tag, aad);
      expect(toHex(recovered), v.description).toBe(toHex(plaintext));
    }
  });

  it('produces different ciphertext than ChaCha20-Poly1305 for same plaintext', () => {
    const v       = xchacha20Poly1305Vectors[0];
    const xchacha = new XChaCha20Poly1305();
    const chacha  = new ChaCha20Poly1305();
    const key     = fromHex(v.key);
    const nonce12 = fromHex(v.nonce).subarray(0, 12);
    const nonce24 = fromHex(v.nonce);
    const pt      = new TextEncoder().encode(v.ptText);
    const { ciphertext: xct } = xchacha.encrypt(key, nonce24, pt);
    const { ciphertext: cct } = chacha.encrypt(key, nonce12, pt);
    expect(toHex(xct)).not.toBe(toHex(cct));
  });

});

// ---------------------------------------------------------------------------
// ChaCha20Poly1305 — functional tests
// ---------------------------------------------------------------------------

describe('ChaCha20Poly1305 — functional tests', () => {
  const aead = new ChaCha20Poly1305();
  const key   = new Uint8Array(32).fill(0x42);
  const nonce = new Uint8Array(12).fill(0x01);

  it('round-trip: 128-byte message', () => {
    const pt = new Uint8Array(128).fill(0xab);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    expect(toHex(aead.decrypt(key, nonce, ciphertext, tag))).toBe(toHex(pt));
  });

  it('round-trip: 256-byte message', () => {
    const pt = new Uint8Array(256).fill(0xcd);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    expect(toHex(aead.decrypt(key, nonce, ciphertext, tag))).toBe(toHex(pt));
  });

  it('round-trip: 512-byte message', () => {
    const pt = new Uint8Array(512).map((_, i) => i & 0xff);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    expect(toHex(aead.decrypt(key, nonce, ciphertext, tag))).toBe(toHex(pt));
  });

  it('round-trip: empty plaintext', () => {
    const pt = new Uint8Array(0);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    expect(ciphertext.length).toBe(0);
    expect(tag.length).toBe(16);
    const recovered = aead.decrypt(key, nonce, ciphertext, tag);
    expect(toHex(recovered)).toBe('');
  });

  it('round-trip: message with AAD', () => {
    const pt  = new TextEncoder().encode('hello world');
    const aad = new TextEncoder().encode('sender=alice');
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
    const recovered = aead.decrypt(key, nonce, ciphertext, tag, aad);
    expect(toHex(recovered)).toBe(toHex(pt));
  });

  it('AAD tamper: single bit flip in AAD → authentication failed', () => {
    const pt  = new TextEncoder().encode('message');
    const aad = new Uint8Array([1, 2, 3, 4]);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
    const badAad = new Uint8Array(aad);
    badAad[0] ^= 0x01;
    expect(() => aead.decrypt(key, nonce, ciphertext, tag, badAad))
      .toThrow('ChaCha20Poly1305: authentication failed');
  });

  it('tag tamper: single bit flip in tag → authentication failed', () => {
    const pt = new Uint8Array([1, 2, 3, 4, 5]);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const badTag = new Uint8Array(tag);
    badTag[0] ^= 0x01;
    expect(() => aead.decrypt(key, nonce, ciphertext, badTag))
      .toThrow('ChaCha20Poly1305: authentication failed');
  });

  it('ciphertext tamper: single bit flip → authentication failed', () => {
    const pt = new Uint8Array([1, 2, 3, 4, 5]);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const badCt = new Uint8Array(ciphertext);
    badCt[0] ^= 0x01;
    expect(() => aead.decrypt(key, nonce, badCt, tag))
      .toThrow('ChaCha20Poly1305: authentication failed');
  });

  it('wrong key → authentication failed', () => {
    const pt  = new TextEncoder().encode('secret');
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const wrongKey = new Uint8Array(32).fill(0xff);
    expect(() => aead.decrypt(wrongKey, nonce, ciphertext, tag))
      .toThrow('ChaCha20Poly1305: authentication failed');
  });

  it('wrong nonce → authentication failed', () => {
    const pt  = new TextEncoder().encode('secret');
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const wrongNonce = new Uint8Array(12).fill(0xff);
    expect(() => aead.decrypt(key, wrongNonce, ciphertext, tag))
      .toThrow('ChaCha20Poly1305: authentication failed');
  });

  it('missing AAD when AAD was used → authentication failed', () => {
    const pt  = new TextEncoder().encode('message');
    const aad = new Uint8Array([0xaa, 0xbb]);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
    expect(() => aead.decrypt(key, nonce, ciphertext, tag))
      .toThrow('ChaCha20Poly1305: authentication failed');
  });

  it('encrypt is deterministic: same inputs → same ciphertext and tag', () => {
    const pt = new TextEncoder().encode('deterministic');
    const r1 = aead.encrypt(key, nonce, pt);
    const r2 = aead.encrypt(key, nonce, pt);
    expect(toHex(r1.ciphertext)).toBe(toHex(r2.ciphertext));
    expect(toHex(r1.tag)).toBe(toHex(r2.tag));
  });

  it('tag is always 16 bytes', () => {
    for (const len of [0, 1, 15, 16, 17, 63, 64, 65, 127, 128]) {
      const { tag } = aead.encrypt(key, nonce, new Uint8Array(len));
      expect(tag.length).toBe(16);
    }
  });

});

// ---------------------------------------------------------------------------
// ChaCha20Poly1305 — input validation
// ---------------------------------------------------------------------------

describe('ChaCha20Poly1305 — input validation', () => {
  const aead = new ChaCha20Poly1305();
  const key   = new Uint8Array(32);
  const nonce = new Uint8Array(12);
  const pt    = new Uint8Array(8);
  const tag   = new Uint8Array(16);

  it('encrypt: wrong key length (16 bytes) throws', () => {
    expect(() => aead.encrypt(new Uint8Array(16), nonce, pt))
      .toThrow('ChaCha20Poly1305: key must be 32 bytes');
  });

  it('encrypt: wrong key length (0 bytes) throws', () => {
    expect(() => aead.encrypt(new Uint8Array(0), nonce, pt))
      .toThrow('ChaCha20Poly1305: key must be 32 bytes');
  });

  it('encrypt: wrong nonce length (8 bytes) throws', () => {
    expect(() => aead.encrypt(key, new Uint8Array(8), pt))
      .toThrow('ChaCha20Poly1305: nonce must be 12 bytes');
  });

  it('encrypt: wrong nonce length (24 bytes) throws', () => {
    expect(() => aead.encrypt(key, new Uint8Array(24), pt))
      .toThrow('ChaCha20Poly1305: nonce must be 12 bytes');
  });

  it('decrypt: wrong key length throws', () => {
    expect(() => aead.decrypt(new Uint8Array(16), nonce, pt, tag))
      .toThrow('ChaCha20Poly1305: key must be 32 bytes');
  });

  it('decrypt: wrong nonce length throws', () => {
    expect(() => aead.decrypt(key, new Uint8Array(8), pt, tag))
      .toThrow('ChaCha20Poly1305: nonce must be 12 bytes');
  });

  it('decrypt: wrong tag length throws', () => {
    expect(() => aead.decrypt(key, nonce, pt, new Uint8Array(15)))
      .toThrow('ChaCha20Poly1305: tag must be 16 bytes');
  });

  it('decrypt: tag length 0 throws', () => {
    expect(() => aead.decrypt(key, nonce, pt, new Uint8Array(0)))
      .toThrow('ChaCha20Poly1305: tag must be 16 bytes');
  });

});

// ---------------------------------------------------------------------------
// XChaCha20Poly1305 — functional tests
// ---------------------------------------------------------------------------

describe('XChaCha20Poly1305 — functional tests', () => {
  const aead = new XChaCha20Poly1305();
  const key   = new Uint8Array(32).fill(0x42);
  const nonce = new Uint8Array(24).fill(0x07); // 24-byte nonce

  it('round-trip: 128-byte message', () => {
    const pt = new Uint8Array(128).fill(0xab);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    expect(toHex(aead.decrypt(key, nonce, ciphertext, tag))).toBe(toHex(pt));
  });

  it('round-trip: message with AAD', () => {
    const pt  = new TextEncoder().encode('hello');
    const aad = new TextEncoder().encode('header');
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
    expect(toHex(aead.decrypt(key, nonce, ciphertext, tag, aad))).toBe(toHex(pt));
  });

  it('round-trip: empty plaintext', () => {
    const pt = new Uint8Array(0);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    expect(ciphertext.length).toBe(0);
    const recovered = aead.decrypt(key, nonce, ciphertext, tag);
    expect(toHex(recovered)).toBe('');
  });

  it('24-byte random nonce round-trips correctly', () => {
    const randomNonce = new Uint8Array(24);
    for (let i = 0; i < 24; i++) randomNonce[i] = (Math.random() * 256) | 0;
    const pt = new TextEncoder().encode('nonce test');
    const { ciphertext, tag } = aead.encrypt(key, randomNonce, pt);
    expect(toHex(aead.decrypt(key, randomNonce, ciphertext, tag))).toBe(toHex(pt));
  });

  it('different nonces produce different ciphertexts for same plaintext', () => {
    const pt     = new Uint8Array(32).fill(0xff);
    const nonce1 = new Uint8Array(24).fill(0x01);
    const nonce2 = new Uint8Array(24).fill(0x02);
    const { ciphertext: ct1 } = aead.encrypt(key, nonce1, pt);
    const { ciphertext: ct2 } = aead.encrypt(key, nonce2, pt);
    expect(toHex(ct1)).not.toBe(toHex(ct2));
  });

  it('HChaCha20 produces different subkeys for different nonce prefixes', () => {
    const pt     = new Uint8Array(32);
    const nonce1 = new Uint8Array(24).fill(0x01);
    const nonce2 = new Uint8Array(24).fill(0x01);
    nonce2[0] = 0x02; // change prefix byte → different subkey
    const { ciphertext: ct1 } = aead.encrypt(key, nonce1, pt);
    const { ciphertext: ct2 } = aead.encrypt(key, nonce2, pt);
    expect(toHex(ct1)).not.toBe(toHex(ct2));
  });

  it('tag tamper → XChaCha20Poly1305: authentication failed', () => {
    const pt = new Uint8Array([1, 2, 3]);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const badTag = new Uint8Array(tag);
    badTag[7] ^= 0x80;
    expect(() => aead.decrypt(key, nonce, ciphertext, badTag))
      .toThrow('XChaCha20Poly1305: authentication failed');
  });

  it('ciphertext tamper → XChaCha20Poly1305: authentication failed', () => {
    const pt = new Uint8Array(16).fill(0xaa);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const badCt = new Uint8Array(ciphertext);
    badCt[0] ^= 0xff;
    expect(() => aead.decrypt(key, nonce, badCt, tag))
      .toThrow('XChaCha20Poly1305: authentication failed');
  });

  it('wrong key → XChaCha20Poly1305: authentication failed', () => {
    const pt  = new TextEncoder().encode('xchacha test');
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const wrongKey = new Uint8Array(32).fill(0x00);
    expect(() => aead.decrypt(wrongKey, nonce, ciphertext, tag))
      .toThrow('XChaCha20Poly1305: authentication failed');
  });

  it('AAD tamper → XChaCha20Poly1305: authentication failed', () => {
    const pt  = new TextEncoder().encode('message');
    const aad = new Uint8Array([0x01, 0x02]);
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt, aad);
    const badAad = new Uint8Array([0x01, 0x03]);
    expect(() => aead.decrypt(key, nonce, ciphertext, tag, badAad))
      .toThrow('XChaCha20Poly1305: authentication failed');
  });

});

// ---------------------------------------------------------------------------
// XChaCha20Poly1305 — input validation
// ---------------------------------------------------------------------------

describe('XChaCha20Poly1305 — input validation', () => {
  const aead = new XChaCha20Poly1305();
  const key   = new Uint8Array(32);
  const nonce = new Uint8Array(24);
  const pt    = new Uint8Array(8);
  const tag   = new Uint8Array(16);

  it('encrypt: wrong key length throws', () => {
    expect(() => aead.encrypt(new Uint8Array(16), nonce, pt))
      .toThrow('XChaCha20Poly1305: key must be 32 bytes');
  });

  it('encrypt: wrong nonce length (12 bytes) throws', () => {
    expect(() => aead.encrypt(key, new Uint8Array(12), pt))
      .toThrow('XChaCha20Poly1305: nonce must be 24 bytes');
  });

  it('encrypt: wrong nonce length (0 bytes) throws', () => {
    expect(() => aead.encrypt(key, new Uint8Array(0), pt))
      .toThrow('XChaCha20Poly1305: nonce must be 24 bytes');
  });

  it('decrypt: wrong key length throws', () => {
    expect(() => aead.decrypt(new Uint8Array(31), nonce, pt, tag))
      .toThrow('XChaCha20Poly1305: key must be 32 bytes');
  });

  it('decrypt: wrong nonce length throws', () => {
    expect(() => aead.decrypt(key, new Uint8Array(23), pt, tag))
      .toThrow('XChaCha20Poly1305: nonce must be 24 bytes');
  });

  it('decrypt: wrong tag length throws', () => {
    expect(() => aead.decrypt(key, nonce, pt, new Uint8Array(8)))
      .toThrow('XChaCha20Poly1305: tag must be 16 bytes');
  });

});

// ---------------------------------------------------------------------------
// Constant-time verification smoke test
// ---------------------------------------------------------------------------

describe('Constant-time verification smoke test', () => {

  // This test times correct vs incorrect tag verification.
  // It does NOT assert on timing values — timing tests are inherently flaky.
  // The purpose is to make timing behavior visible in CI output.
  it('timing smoke: correct vs incorrect tag verification (1000 rounds each)', () => {
    const aead = new ChaCha20Poly1305();
    const key   = new Uint8Array(32).fill(0x01);
    const nonce = new Uint8Array(12).fill(0x02);
    const pt    = new TextEncoder().encode('timing test payload');
    const { ciphertext, tag } = aead.encrypt(key, nonce, pt);
    const badTag = new Uint8Array(tag);
    badTag[0] ^= 0xff;

    const N = 1000;

    const t0 = performance.now();
    for (let i = 0; i < N; i++) {
      aead.decrypt(key, nonce, ciphertext, tag);
    }
    const correctMs = performance.now() - t0;

    const t1 = performance.now();
    for (let i = 0; i < N; i++) {
      try { aead.decrypt(key, nonce, ciphertext, badTag); } catch (_) { /* expected */ }
    }
    const wrongMs = performance.now() - t1;

    console.log(
      `[timing smoke] correct tag: ${correctMs.toFixed(1)} ms / ${N} calls` +
      ` | wrong tag: ${wrongMs.toFixed(1)} ms / ${N} calls`,
    );

    // Both paths must complete within 10 seconds
    expect(correctMs).toBeLessThan(10_000);
    expect(wrongMs).toBeLessThan(10_000);
  });

});
