///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (marco@paland.com)
//             2015, PALANDesign Hannover, Germany
//
// \license The MIT License (MIT)
//
// This file is part of the leviathan crypto library.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// \brief block cipher modes implementation
// usage: var aes = new leviathan.blockmode(new leviathan.rijndael())
//
///////////////////////////////////////////////////////////////////////////////

import { Blockcipher, constantTimeEqual } from './base';


export class CBC {
  blockcipher: Blockcipher;

  /**
   * CBC ctor
   * @param {Object} blockcipher The block cipher algorithm to use
   */
  constructor(blockcipher: Blockcipher) {
    this.blockcipher = blockcipher;
  }

  /**
   * CBC mode encryption
   */
  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    let bs = this.blockcipher.blockSize,
        ct = new Uint8Array(pt.length),
        et = new Uint8Array(bs);

    // process first block
    for (let f = 0; f < bs; f++) {
      et[f] = pt[f] ^ (iv[f] || 0);
    }
    ct.set(this.blockcipher.encrypt(key, et), 0);

    // process the other blocks
    for (let b = 1, len = pt.length / bs; b < len; b++) {
      for (let i = 0; i < bs; i++) {
        et[i] = pt[i + (b * bs)] ^ ct[i + ((b - 1) * bs)];
      }
      ct.set(this.blockcipher.encrypt(key, et), b * bs);
    }
    return ct;
  }

  /**
   * CBC mode decryption
   */
  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    let bs = this.blockcipher.blockSize,
        pt = new Uint8Array(ct.length);

    // process first block
    pt.set(this.blockcipher.decrypt(key, ct.subarray(0, bs)), 0);
    for (let i = 0, len = bs; i < len; i++) {
      pt[i] = pt[i] ^ (iv[i] || 0);
    }

    // process other blocks
    for (let b = 1, l = ct.length / bs; b < l; b++) {
      pt.set(this.blockcipher.decrypt(key, ct.subarray(b * bs, (b + 1) * bs)), b * bs);
      for (let i = 0; i < bs; i++) {
        pt[i + (b * bs)] = pt[i + (b * bs)] ^ ct[i + ((b - 1) * bs)];
      }
    }
    return pt;
  }
}

//////////////////////////////////////////////////////////////////////////

export class CTR {
  blockcipher: Blockcipher;
  ctr: Uint8Array;

  /**
   * CTR ctor
   * @param {Object} blockcipher The block cipher algorithm to use
   */
  constructor(blockcipher: Blockcipher) {
    this.blockcipher = blockcipher;

    // init counter
    this.ctr = new Uint8Array(this.blockcipher.blockSize);
  }

  /**
   * CTR mode encryption
   */
  encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array {
    let bs = this.blockcipher.blockSize,
        ct = new Uint8Array(pt.length);

    this.ctr.set(iv || this.ctr);

    // process blocks
    for (let b = 0, len = pt.length / bs; b < len; b++) {
      ct.set(this.blockcipher.encrypt(key, this.ctr), b * bs);
      for (let i = 0; i < bs; i++) {
        ct[i + (b * bs)] ^= pt[i + (b * bs)];
      }

      // increment the counter
      this.ctr[0]++;
      for (let i = 0; i < bs - 1; i++) {
        if (this.ctr[i] === 0) {
          this.ctr[i + 1]++;
        }
        else break;
      }
    }
    return ct;
  }

  /**
   * CTR mode decryption
   */
  decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array {
    let bs = this.blockcipher.blockSize,
        pt = new Uint8Array(ct.length);

    this.ctr.set(iv || this.ctr);

    // process blocks
    for (let b = 0, len = ct.length / bs; b < len; b++) {
      pt.set(this.blockcipher.encrypt(key, this.ctr), b * bs);
      for (let i = 0; i < bs; i++) {
        pt[i + (b * bs)] ^= ct[i + (b * bs)];
      }

      // increment the counter
      this.ctr[0]++;
      for (let i = 0; i < bs - 1; i++) {
        if (this.ctr[i] === 0) {
          this.ctr[i + 1]++;
        }
        else break;
      }
    }
    return pt;
  }
}

// ============================================================
// ChaCha20-Poly1305 and XChaCha20-Poly1305 (RFC 8439)
// ============================================================
//
// Private module-level helpers — not exported from index.ts.
// Test-only exports are prefixed with underscore.

// Read 4 bytes from byte array at offset i as a little-endian uint32.
function u8to32le(x: Uint8Array, i: number): number {
  return ((x[i] | (x[i + 1] << 8) | (x[i + 2] << 16) | (x[i + 3] << 24)) >>> 0);
}

// Write uint32 v to byte array at offset i as little-endian.
function u32to8le(x: Uint8Array, i: number, v: number): void {
  x[i]     =  v         & 0xff;
  x[i + 1] = (v >>>  8) & 0xff;
  x[i + 2] = (v >>> 16) & 0xff;
  x[i + 3] = (v >>> 24) & 0xff;
}

// ChaCha20 quarter round per RFC 8439 §2.1.
// Operates on four positions a, b, c, d of the Uint32Array state.
function qr(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] += s[b]; let t = s[d] ^ s[a]; s[d] = (t << 16) | (t >>> 16);
  s[c] += s[d];     t = s[b] ^ s[c]; s[b] = (t << 12) | (t >>> 20);
  s[a] += s[b];     t = s[d] ^ s[a]; s[d] = (t <<  8) | (t >>> 24);
  s[c] += s[d];     t = s[b] ^ s[c]; s[b] = (t <<  7) | (t >>> 25);
}

/**
 * ChaCha20 block function per RFC 8439 §2.3 — IETF variant.
 * Accepts a 256-bit key, 32-bit counter, and 96-bit (12-byte) nonce.
 * Returns 64 bytes of keystream.
 *
 * NOTE: This is the IETF ChaCha20, not the original Bernstein variant
 * (which uses a 64-bit nonce and 64-bit counter). The existing ChaCha20
 * class uses the original variant; this function is needed for AEAD.
 */
export function _chacha20Block(key: Uint8Array, counter: number, nonce12: Uint8Array): Uint8Array {
  const s = new Uint32Array(16);
  // Constants — "expand 32-byte k"
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  // Key — 8 LE uint32 words
  for (let i = 0; i < 8; i++) s[4 + i] = u8to32le(key, i * 4);
  // Counter (32-bit) and nonce (96-bit = 3 × 32-bit LE words)
  s[12] = counter >>> 0;
  s[13] = u8to32le(nonce12, 0);
  s[14] = u8to32le(nonce12, 4);
  s[15] = u8to32le(nonce12, 8);

  const init = new Uint32Array(s); // save initial state

  // 20 rounds = 10 iterations of column + diagonal rounds
  for (let r = 0; r < 10; r++) {
    qr(s,  0,  4,  8, 12); qr(s,  1,  5,  9, 13);
    qr(s,  2,  6, 10, 14); qr(s,  3,  7, 11, 15);
    qr(s,  0,  5, 10, 15); qr(s,  1,  6, 11, 12);
    qr(s,  2,  7,  8, 13); qr(s,  3,  4,  9, 14);
  }

  // Add initial state (modulo 2^32) and serialize as LE bytes
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) u32to8le(out, i * 4, (s[i] + init[i]) >>> 0);
  return out;
}

/**
 * HChaCha20 subkey derivation per XChaCha20 IETF draft §2.2.
 *
 * Differs from chacha20Block:
 * - Takes a 16-byte input (all 4 of state words 12-15 are filled by nonce16)
 * - Does NOT add initial state to output
 * - Returns only first row (words 0-3) and last row (words 12-15) — 32 bytes total
 */
export function _hchacha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  const s = new Uint32Array(16);
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = u8to32le(key, i * 4);
  for (let i = 0; i < 4; i++) s[12 + i] = u8to32le(nonce16, i * 4);

  for (let r = 0; r < 10; r++) {
    qr(s,  0,  4,  8, 12); qr(s,  1,  5,  9, 13);
    qr(s,  2,  6, 10, 14); qr(s,  3,  7, 11, 15);
    qr(s,  0,  5, 10, 15); qr(s,  1,  6, 11, 12);
    qr(s,  2,  7,  8, 13); qr(s,  3,  4,  9, 14);
  }

  // Output: first 128 bits (words 0-3) and last 128 bits (words 12-15), no initial-state addition
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) u32to8le(out, i * 4,       s[i]);
  for (let i = 0; i < 4; i++) u32to8le(out, 16 + i * 4,  s[12 + i]);
  return out;
}

// Encrypt or decrypt arbitrary-length input with ChaCha20 starting at `counter`.
// Encryption and decryption are identical (XOR with keystream).
function chacha20Crypt(
  key: Uint8Array, counter: number, nonce12: Uint8Array, input: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(input.length);
  for (let pos = 0, blk = counter; pos < input.length; pos += 64, blk++) {
    const ks  = _chacha20Block(key, blk, nonce12);
    const end = Math.min(64, input.length - pos);
    for (let i = 0; i < end; i++) out[pos + i] = input[pos + i] ^ ks[i];
  }
  return out;
}

// Read little-endian bytes as a BigInt.
function leToNum(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

// Serialize a BigInt to little-endian bytes of given length (lower bits only).
function numToLe(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

/**
 * Poly1305 MAC per RFC 8439 §2.5.
 *
 * Uses BigInt for clarity (not limb arithmetic) — RFC 8439 §3 notes that
 * a naive big-number implementation will not exceed 2^288 and is correct.
 *
 * IMPORTANT: `key` is a 32-byte ONE-TIME key (r || s).
 * This key MUST NEVER be reused across messages. In the AEAD construction
 * it is derived fresh for each message from ChaCha20 at counter=0.
 *
 * @param key     32-byte one-time key: first 16 bytes = r (clamped), last 16 = s
 * @param message arbitrary-length message to authenticate
 * @returns       16-byte tag
 */
export function _poly1305Mac(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Parse and clamp r (first 16 bytes, LE integer).
  // Clamping zeroes specific bits per RFC 8439 §2.5.1.
  let r = leToNum(key.subarray(0, 16));
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn; // clamp mask

  const s = leToNum(key.subarray(16, 32)); // parse s (last 16 bytes, LE integer)
  const p = (1n << 130n) - 5n;             // Poly1305 prime
  let acc = 0n;

  const len = message.length;
  for (let i = 0; i < len; i += 16) {
    const blockLen = Math.min(16, len - i);
    // Read block as LE number, then set the bit just above the block's byte count
    // (equivalent to appending a 0x01 byte, per RFC 8439 §2.5)
    let n = leToNum(message.subarray(i, i + blockLen));
    n |= 1n << BigInt(blockLen * 8);
    acc = ((acc + n) * r) % p;
  }

  // Add s and truncate to 128 bits; serialize as LE
  acc = (acc + s) & ((1n << 128n) - 1n);
  return numToLe(acc, 16);
}

/**
 * Generate the Poly1305 one-time key for a given (key, nonce) pair.
 * Calls ChaCha20 at counter=0 and takes the first 32 bytes (RFC 8439 §2.6).
 */
export function _poly1305KeyGen(key: Uint8Array, nonce12: Uint8Array): Uint8Array {
  return _chacha20Block(key, 0, nonce12).subarray(0, 32);
}

// Build the AEAD MAC input buffer per RFC 8439 §2.8.1:
//   aad || pad16(aad) || ciphertext || pad16(ciphertext) || LE64(aad.len) || LE64(ct.len)
function buildAeadMacInput(aad: Uint8Array, ct: Uint8Array): Uint8Array {
  const p16 = (n: number) => (n % 16 === 0 ? 0 : 16 - (n % 16));
  const buf = new Uint8Array(aad.length + p16(aad.length) + ct.length + p16(ct.length) + 16);
  let pos = 0;
  buf.set(aad, pos); pos += aad.length + p16(aad.length);
  buf.set(ct,  pos); pos += ct.length  + p16(ct.length);
  // LE64(aad.length) — lengths fit in 32 bits for any practical input
  let n = aad.length;
  for (let i = 0; i < 4; i++) { buf[pos++] = n & 0xff; n >>>= 8; }
  pos += 4; // high 32 bits remain zero
  n = ct.length;
  for (let i = 0; i < 4; i++) { buf[pos++] = n & 0xff; n >>>= 8; }
  // final 4 bytes remain zero
  return buf;
}

// ============================================================
// Public AEAD classes
// ============================================================

/**
 * AEAD_CHACHA20_POLY1305 per RFC 8439.
 *
 * Combined authenticated encryption: ChaCha20 for confidentiality,
 * Poly1305 for integrity and authenticity. Standardized in RFC 8439;
 * used in TLS 1.3, WireGuard, and SSH.
 *
 * **Nonce uniqueness is critical.** Reusing a (key, nonce) pair destroys
 * confidentiality: XOR of two ciphertexts = XOR of two plaintexts.
 * The 96-bit nonce is too short for random generation at scale.
 * Prefer {@link XChaCha20Poly1305} when nonces are generated randomly.
 *
 * Key:   256-bit (32 bytes)
 * Nonce: 96-bit (12 bytes) — use a counter or derive deterministically
 */
export class ChaCha20Poly1305 {
  /**
   * Encrypt and authenticate plaintext.
   *
   * @param key       256-bit key (32 bytes)
   * @param nonce     96-bit nonce (12 bytes). MUST be unique per (key, message).
   *                  Use a counter or derive deterministically. Do NOT generate
   *                  randomly — use XChaCha20Poly1305 for random nonces.
   * @param plaintext message to encrypt (any length including zero)
   * @param aad       additional authenticated data (not encrypted, authenticated)
   * @returns `{ ciphertext, tag }` — ciphertext.length === plaintext.length, tag is 16 bytes
   */
  encrypt(
    key:       Uint8Array,
    nonce:     Uint8Array,
    plaintext: Uint8Array,
    aad:       Uint8Array = new Uint8Array(0),
  ): { ciphertext: Uint8Array; tag: Uint8Array } {
    if (key.length !== 32)   throw new Error('ChaCha20Poly1305: key must be 32 bytes');
    if (nonce.length !== 12) throw new Error('ChaCha20Poly1305: nonce must be 12 bytes');
    const poly1305Key = _poly1305KeyGen(key, nonce);
    const ciphertext  = chacha20Crypt(key, 1, nonce, plaintext);
    const tag         = _poly1305Mac(poly1305Key, buildAeadMacInput(aad, ciphertext));
    return { ciphertext, tag };
  }

  /**
   * Verify and decrypt ciphertext.
   *
   * **Always verifies the Poly1305 tag before decrypting.**
   * Uses constant-time comparison for tag verification — safe against timing attacks.
   *
   * @param key        256-bit key (32 bytes)
   * @param nonce      96-bit nonce (12 bytes) — must match the value used to encrypt
   * @param ciphertext ciphertext to decrypt
   * @param tag        16-byte authentication tag produced by encrypt()
   * @param aad        additional authenticated data (must match value used to encrypt)
   * @returns plaintext on success
   * @throws Error('ChaCha20Poly1305: authentication failed') if tag does not match
   */
  decrypt(
    key:        Uint8Array,
    nonce:      Uint8Array,
    ciphertext: Uint8Array,
    tag:        Uint8Array,
    aad:        Uint8Array = new Uint8Array(0),
  ): Uint8Array {
    if (key.length !== 32)   throw new Error('ChaCha20Poly1305: key must be 32 bytes');
    if (nonce.length !== 12) throw new Error('ChaCha20Poly1305: nonce must be 12 bytes');
    if (tag.length !== 16)   throw new Error('ChaCha20Poly1305: tag must be 16 bytes');
    const poly1305Key = _poly1305KeyGen(key, nonce);
    const expectedTag = _poly1305Mac(poly1305Key, buildAeadMacInput(aad, ciphertext));
    // Constant-time comparison — never use === or Buffer.equals() for MAC comparison
    if (!constantTimeEqual(expectedTag, tag)) {
      throw new Error('ChaCha20Poly1305: authentication failed');
    }
    return chacha20Crypt(key, 1, nonce, ciphertext);
  }
}

/**
 * AEAD_XChaCha20_Poly1305 per XChaCha20 IETF draft (draft-irtf-cfrg-xchacha-03).
 *
 * Extends ChaCha20-Poly1305 with a 192-bit nonce (vs 96-bit). The larger nonce
 * makes random generation safe — 2^96 messages expected before collision at 50%
 * probability, compared to 2^48 for 96-bit nonces.
 *
 * **Recommended for new applications.** Use ChaCha20Poly1305 only when
 * RFC 8439 interoperability with 96-bit nonces is required.
 *
 * Construction: derive a subkey from key + nonce[0..15] via HChaCha20,
 * then run AEAD_CHACHA20_POLY1305 with subkey + [0x00×4 || nonce[16..23]].
 *
 * Key:   256-bit (32 bytes)
 * Nonce: 192-bit (24 bytes) — safe to generate randomly via crypto.getRandomValues
 */
export class XChaCha20Poly1305 {
  private readonly _inner = new ChaCha20Poly1305();

  /**
   * Encrypt and authenticate plaintext using XChaCha20-Poly1305.
   *
   * @param key       256-bit key (32 bytes)
   * @param nonce     192-bit nonce (24 bytes). Safe to generate randomly.
   * @param plaintext message to encrypt
   * @param aad       additional authenticated data
   * @returns `{ ciphertext, tag }` — ciphertext.length === plaintext.length, tag is 16 bytes
   */
  encrypt(
    key:       Uint8Array,
    nonce:     Uint8Array,
    plaintext: Uint8Array,
    aad:       Uint8Array = new Uint8Array(0),
  ): { ciphertext: Uint8Array; tag: Uint8Array } {
    if (key.length !== 32)   throw new Error('XChaCha20Poly1305: key must be 32 bytes');
    if (nonce.length !== 24) throw new Error('XChaCha20Poly1305: nonce must be 24 bytes');
    const subkey       = _hchacha20(key, nonce.subarray(0, 16));
    const innerNonce   = new Uint8Array(12);              // zero-initialized
    innerNonce.set(nonce.subarray(16, 24), 4);            // bytes 0-3 = 0x00, bytes 4-11 = nonce[16..23]
    return this._inner.encrypt(subkey, innerNonce, plaintext, aad);
  }

  /**
   * Verify and decrypt ciphertext using XChaCha20-Poly1305.
   *
   * Always verifies the tag before returning plaintext.
   * Uses constant-time tag comparison.
   *
   * @throws Error('XChaCha20Poly1305: authentication failed') if tag is invalid
   */
  decrypt(
    key:        Uint8Array,
    nonce:      Uint8Array,
    ciphertext: Uint8Array,
    tag:        Uint8Array,
    aad:        Uint8Array = new Uint8Array(0),
  ): Uint8Array {
    if (key.length !== 32)   throw new Error('XChaCha20Poly1305: key must be 32 bytes');
    if (nonce.length !== 24) throw new Error('XChaCha20Poly1305: nonce must be 24 bytes');
    if (tag.length !== 16)   throw new Error('XChaCha20Poly1305: tag must be 16 bytes');
    const subkey     = _hchacha20(key, nonce.subarray(0, 16));
    const innerNonce = new Uint8Array(12);
    innerNonce.set(nonce.subarray(16, 24), 4);
    try {
      return this._inner.decrypt(subkey, innerNonce, ciphertext, tag, aad);
    } catch (_e) {
      // Re-throw with XChaCha20Poly1305-specific message
      throw new Error('XChaCha20Poly1305: authentication failed');
    }
  }
}
