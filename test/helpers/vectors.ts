///////////////////////////////////////////////////////////////////////////////
// Shared test helpers for Serpent audit test suite
// Phase 4 of the Serpent256 Cryptographic Audit
///////////////////////////////////////////////////////////////////////////////

import { readFileSync } from 'fs';
import { resolve } from 'path';

// ─────────────────────────────────────────────────────────────────────────────
// Paths
// ─────────────────────────────────────────────────────────────────────────────

const VECTORS_DIR = resolve(__dirname, '../vectors');

export function readVector(name: string): string {
  return readFileSync(resolve(VECTORS_DIR, name), 'utf8');
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte utilities
// ─────────────────────────────────────────────────────────────────────────────

export function hex2bytes(hex: string): Uint8Array {
  const h = hex.replace(/\s/g, '').toLowerCase();
  const arr = new Uint8Array(h.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

export function bytes2hex(arr: Uint8Array): string {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: ecb_vt.txt — Variable Text KAT
// Format: KEYSIZE=N  KEY=hex  (then per-entry: I=n  PT=hex  CT=hex)
// ─────────────────────────────────────────────────────────────────────────────

export interface KatVector {
  keysize: number;
  key: string;   // hex, length = keysize/4 chars
  pt: string;
  ct: string;
}

export function parseVt(text: string): KatVector[] {
  const vectors: KatVector[] = [];
  const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
  let keysize = 0;
  let key = '';
  for (let li = 0; li < lines.length; li++) {
    const t = lines[li];
    if (t.startsWith('KEYSIZE=')) { keysize = parseInt(t.slice(8)); continue; }
    if (t.startsWith('KEY=')) { key = t.slice(4).toLowerCase(); continue; }
    if (t.startsWith('I=')) {
      // Next non-blank line should be PT=, then CT=
      let ptLine = '', ctLine = '';
      for (let j = li + 1; j < li + 5 && j < lines.length; j++) {
        if (!ptLine && lines[j].startsWith('PT=')) ptLine = lines[j];
        if (!ctLine && lines[j].startsWith('CT=')) ctLine = lines[j];
        if (ptLine && ctLine) break;
      }
      if (ptLine && ctLine) {
        vectors.push({ keysize, key, pt: ptLine.slice(3).toLowerCase(), ct: ctLine.slice(3).toLowerCase() });
      }
    }
  }
  return vectors;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: ecb_vk.txt — Variable Key KAT
// Format: KEYSIZE=N  PT=hex  (then per-entry: I=n  KEY=hex  CT=hex)
// ─────────────────────────────────────────────────────────────────────────────

export function parseVk(text: string): KatVector[] {
  const vectors: KatVector[] = [];
  const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
  let keysize = 0;
  let pt = '';
  for (let li = 0; li < lines.length; li++) {
    const t = lines[li];
    if (t.startsWith('KEYSIZE=')) { keysize = parseInt(t.slice(8)); continue; }
    if (t.startsWith('PT=')) { pt = t.slice(3).toLowerCase(); continue; }
    if (t.startsWith('I=')) {
      let keyLine = '', ctLine = '';
      for (let j = li + 1; j < li + 5 && j < lines.length; j++) {
        if (!keyLine && lines[j].startsWith('KEY=')) keyLine = lines[j];
        if (!ctLine && lines[j].startsWith('CT=')) ctLine = lines[j];
        if (keyLine && ctLine) break;
      }
      if (keyLine && ctLine) {
        vectors.push({ keysize, key: keyLine.slice(4).toLowerCase(), pt, ct: ctLine.slice(3).toLowerCase() });
      }
    }
  }
  return vectors;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: ecb_tbl.txt — S-Box Entry KAT (same format as ecb_vt.txt)
// ─────────────────────────────────────────────────────────────────────────────

export const parseTbl = parseVt;

// ─────────────────────────────────────────────────────────────────────────────
// Parser: ECB Monte Carlo files (ecb_e_m.txt, ecb_d_m.txt)
// ecb_e_m: I=n  KEY=hex  PT=hex  CT=hex
// ecb_d_m: I=n  KEY=hex  CT=hex  PT=hex   (reversed PT/CT order!)
// ─────────────────────────────────────────────────────────────────────────────

export interface McEcbVector {
  keysize: number;
  idx: number;
  key: string;
  pt: string;   // initial plaintext (encrypt) or final plaintext (decrypt)
  ct: string;   // final ciphertext (encrypt) or initial ciphertext (decrypt)
}

function parseMcEcbInner(text: string, ctBeforePt: boolean): McEcbVector[] {
  const vectors: McEcbVector[] = [];
  const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
  let keysize = 0;
  for (let li = 0; li < lines.length; li++) {
    const t = lines[li];
    if (t.startsWith('KEYSIZE=')) { keysize = parseInt(t.slice(8)); continue; }
    if (t.startsWith('I=')) {
      const idx = parseInt(t.slice(2));
      // Collect next 3 non-empty lines
      const fields: string[] = [];
      for (let j = li + 1; j < lines.length && fields.length < 3; j++) {
        if (lines[j]) fields.push(lines[j]);
      }
      if (fields.length < 3) continue;
      const keyLine = fields[0]; // always KEY=
      const f1 = fields[ctBeforePt ? 2 : 1]; // PT or CT depending on format
      const f2 = fields[ctBeforePt ? 1 : 2]; // CT or PT depending on format
      if (keyLine.startsWith('KEY=') && f1.startsWith('PT=') && f2.startsWith('CT=')) {
        vectors.push({
          keysize, idx,
          key: keyLine.slice(4).toLowerCase(),
          pt:  f1.slice(3).toLowerCase(),
          ct:  f2.slice(3).toLowerCase(),
        });
      }
    }
  }
  return vectors;
}

/** Parse ecb_e_m.txt: KEY, PT, CT order */
export function parseMcEcbEncrypt(text: string): McEcbVector[] {
  return parseMcEcbInner(text, false);
}

/** Parse ecb_d_m.txt: KEY, CT, PT order (reversed!) */
export function parseMcEcbDecrypt(text: string): McEcbVector[] {
  return parseMcEcbInner(text, true);
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: CBC Monte Carlo files (cbc_e_m.txt, cbc_d_m.txt)
// cbc_e_m: I=n  KEY=hex  IV=hex  PT=hex  CT=hex
// cbc_d_m: I=n  KEY=hex  IV=hex  CT=hex  PT=hex  (reversed PT/CT!)
// ─────────────────────────────────────────────────────────────────────────────

export interface McCbcVector {
  keysize: number;
  idx: number;
  key: string;
  iv: string;
  pt: string;
  ct: string;
}

function parseMcCbcInner(text: string, ctBeforePt: boolean): McCbcVector[] {
  const vectors: McCbcVector[] = [];
  const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
  let keysize = 0;
  for (let li = 0; li < lines.length; li++) {
    const t = lines[li];
    if (t.startsWith('KEYSIZE=')) { keysize = parseInt(t.slice(8)); continue; }
    if (t.startsWith('I=')) {
      const idx = parseInt(t.slice(2));
      const fields: string[] = [];
      for (let j = li + 1; j < lines.length && fields.length < 4; j++) {
        if (lines[j]) fields.push(lines[j]);
      }
      if (fields.length < 4) continue;
      const keyLine = fields[0];
      const ivLine  = fields[1];
      const f1 = fields[ctBeforePt ? 3 : 2];
      const f2 = fields[ctBeforePt ? 2 : 3];
      if (keyLine.startsWith('KEY=') && ivLine.startsWith('IV=') &&
          f1.startsWith('PT=') && f2.startsWith('CT=')) {
        vectors.push({
          keysize, idx,
          key: keyLine.slice(4).toLowerCase(),
          iv:  ivLine.slice(3).toLowerCase(),
          pt:  f1.slice(3).toLowerCase(),
          ct:  f2.slice(3).toLowerCase(),
        });
      }
    }
  }
  return vectors;
}

/** Parse cbc_e_m.txt: KEY, IV, PT, CT order */
export function parseMcCbcEncrypt(text: string): McCbcVector[] {
  return parseMcCbcInner(text, false);
}

/** Parse cbc_d_m.txt: KEY, IV, CT, PT order (reversed!) */
export function parseMcCbcDecrypt(text: string): McCbcVector[] {
  return parseMcCbcInner(text, true);
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: ecb_iv.txt — Intermediate Values
// Parses: KEY, LONG_KEY, SK[0..32], SK^[0..32], PT, R[0..31], CT
// ─────────────────────────────────────────────────────────────────────────────

export interface IvTestCase {
  keysize: number;
  key: string;
  longKey: string;
  sk: string[];       // bitslice subkeys SK[0..32]
  skHat: string[];    // conventional subkeys SK^[0..32]
  pt: string;
  r: string[];        // R[0..31] round outputs
  ct: string;
}

export function parseIv(text: string): IvTestCase[] {
  const cases: IvTestCase[] = [];
  let keysize = 0;
  let current: Partial<IvTestCase> | null = null;
  const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));

  function flush() {
    if (current?.pt && current.ct && current.sk) {
      cases.push(current as IvTestCase);
    }
    current = null;
  }

  for (const t of lines) {
    if (t.startsWith('KEYSIZE=')) {
      flush();
      keysize = parseInt(t.slice(8));
    } else if (t.startsWith('KEY=') && !t.startsWith('KEYSIZE=')) {
      flush();
      current = { keysize, key: t.slice(4).toLowerCase(), sk: [], skHat: [], r: [] };
    } else if (current) {
      if (t.startsWith('LONG_KEY=')) {
        current.longKey = t.slice(9).toLowerCase();
      } else if (/^SK\[(\d+)\]=/.test(t)) {
        const m = t.match(/^SK\[(\d+)\]=(.+)$/);
        if (m) current.sk![parseInt(m[1])] = m[2].toLowerCase();
      } else if (/^SK\^\[(\d+)\]=/.test(t)) {
        const m = t.match(/^SK\^\[(\d+)\]=(.+)$/);
        if (m) current.skHat![parseInt(m[1])] = m[2].toLowerCase();
      } else if (t.startsWith('PT=')) {
        // Only capture the first PT= (section 1: encrypt T)
        if (!current.pt) current.pt = t.slice(3).toLowerCase();
      } else if (/^R\[(\d+)\]=/.test(t)) {
        // Only capture R[] from section 1 (before the first CT= line)
        if (!current.ct) {
          const m = t.match(/^R\[(\d+)\]=(.+)$/);
          if (m) current.r![parseInt(m[1])] = m[2].toLowerCase();
        }
      } else if (t.startsWith('CT=') && !current.ct) {
        current.ct = t.slice(3).toLowerCase();
      }
    }
  }
  flush();
  return cases;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser: NESSIE vectors
// ─────────────────────────────────────────────────────────────────────────────

export interface NessieVector {
  key: string;    // 256-bit key hex (64 chars)
  plain: string;  // plaintext hex (32 chars)
  cipher: string; // expected ciphertext hex (32 chars)
}

export function parseNessie(text: string): NessieVector[] {
  const vectors: NessieVector[] = [];
  const lines = text.split('\n').map(l => l.trim().replace(/\r$/, ''));
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i];
    if (t.toLowerCase().startsWith('key=')) {
      const k1 = t.replace(/^key=\s*/i, '').replace(/\s/g, '').toLowerCase();
      const k2 = (lines[i + 1] ?? '').replace(/\s/g, '').toLowerCase();
      const key = k1 + k2;
      let plain = '', cipher = '';
      for (let j = i + 2; j < i + 12 && j < lines.length; j++) {
        const l = lines[j].toLowerCase();
        if (l.startsWith('plain='))  plain  = lines[j].replace(/^plain=\s*/i, '').replace(/\s/g, '').toLowerCase();
        if (l.startsWith('cipher=')) cipher = lines[j].replace(/^cipher=\s*/i, '').replace(/\s/g, '').toLowerCase();
        if (plain && cipher) break;
      }
      if (key.length === 64 && plain.length === 32 && cipher.length === 32) {
        vectors.push({ key, plain, cipher });
      }
    }
  }
  return vectors;
}

// ─────────────────────────────────────────────────────────────────────────────
// NESSIE preprocessing (from CLAUDE.md project instructions):
//
// The NESSIE test vectors use big-endian word order; leviathan uses the original
// AES submission format (little-endian words, reversed key). To convert:
//
//   1. Split the 256-bit key into 8 DWORDs and REVERSE their order
//   2. Byte-swap each DWORD to little-endian
//   3. Byte-swap each 32-bit word of the plaintext to little-endian
//
// §CLAUDE.md lines 168-171
// ─────────────────────────────────────────────────────────────────────────────

export function nessiePreprocessKey(keyHex: string): Uint8Array {
  // Parse 8 big-endian uint32 words from the 256-bit key
  const words: number[] = [];
  for (let i = 0; i < 8; i++) {
    words.push(parseInt(keyHex.slice(i * 8, i * 8 + 8), 16) >>> 0);
  }
  // Reverse word order
  words.reverse();
  // Byte-swap each word (big-endian → little-endian in bytes)
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const w = words[i];
    out[i * 4 + 0] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>>  8) & 0xff;
    out[i * 4 + 3] = (w >>>  0) & 0xff;
  }
  return out;
}

export function nessiePreprocessPlaintext(ptHex: string): Uint8Array {
  // Byte-swap each 32-bit word of the plaintext to little-endian
  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    const w = parseInt(ptHex.slice(i * 8, i * 8 + 8), 16) >>> 0;
    out[i * 4 + 0] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>>  8) & 0xff;
    out[i * 4 + 3] = (w >>>  0) & 0xff;
  }
  return out;
}

// Post-process leviathan ciphertext back to NESSIE format for comparison
export function nessiePostprocessCiphertext(ct: Uint8Array): string {
  // Reverse of plaintext preprocessing: byte-swap each word, then read as BE
  let hex = '';
  for (let i = 0; i < 4; i++) {
    const b0 = ct[i * 4 + 0], b1 = ct[i * 4 + 1], b2 = ct[i * 4 + 2], b3 = ct[i * 4 + 3];
    // bytes are stored big-endian per leviathan output convention
    hex += b0.toString(16).padStart(2, '0');
    hex += b1.toString(16).padStart(2, '0');
    hex += b2.toString(16).padStart(2, '0');
    hex += b3.toString(16).padStart(2, '0');
  }
  return hex.toUpperCase();
}

// ─────────────────────────────────────────────────────────────────────────────
// IP/FP permutation helpers for ecb_iv.txt intermediate value comparison.
//
// R[i] in ecb_iv.txt is in CONVENTIONAL representation.
// leviathan's internal bitslice state after round i = IP(R[i]).
//
// IPTable[p] = (p & 3) * 32 + (p >> 2)   (from serpent-tables.h)
// FPTable[v] = 4 * (v & 31) + (v >> 5)   (IP inverse)
//
// §serpent-tables.h
// ─────────────────────────────────────────────────────────────────────────────

/** Convert a 32-char hex string to 4 big-endian uint32 words. */
export function hex2words(hex: string): number[] {
  return [
    parseInt(hex.slice( 0,  8), 16) >>> 0,
    parseInt(hex.slice( 8, 16), 16) >>> 0,
    parseInt(hex.slice(16, 24), 16) >>> 0,
    parseInt(hex.slice(24, 32), 16) >>> 0,
  ];
}

/** Convert 4 big-endian uint32 words to a 32-char hex string. */
export function words2hex(w: number[]): string {
  return w.map(v => (v >>> 0).toString(16).padStart(8, '0')).join('');
}

/**
 * Apply the Serpent initial permutation (IP) to four 32-bit words.
 * IP converts conventional representation to bitslice representation.
 * IPTable[p] = (p & 3) * 32 + (p >> 2)
 */
export function applyIP(w: number[]): number[] {
  const out = [0, 0, 0, 0];
  for (let p = 0; p < 128; p++) {
    const v = (p & 3) * 32 + (p >> 2);
    const bit = (w[v >> 5] >>> (v & 31)) & 1;
    if (bit) out[p >> 5] |= (1 << (p & 31));
  }
  return out;
}

/**
 * Apply the Serpent final permutation (FP = IP^{-1}) to four 32-bit words.
 * FPTable[v] = 4*(v&31) + (v>>5)
 */
export function applyFP(w: number[]): number[] {
  const out = [0, 0, 0, 0];
  for (let q = 0; q < 128; q++) {
    const v = 4 * (q & 31) + (q >> 5);
    const bit = (w[v >> 5] >>> (v & 31)) & 1;
    if (bit) out[q >> 5] |= (1 << (q & 31));
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key padding helper: pads a hex key string to the correct length for leviathan
// (leviathan accepts 16, 24, or 32 byte keys for 128/192/256-bit keys)
// ─────────────────────────────────────────────────────────────────────────────

export function padKey(keyHex: string, keysize: number): Uint8Array {
  // keysize in bits; keysize/4 = hex chars needed
  const needed = keysize / 4;
  const padded = keyHex.padEnd(needed, '0').slice(0, needed);
  return hex2bytes(padded);
}
