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
// ECB Monte Carlo Tests — ecb_e_m.txt and ecb_d_m.txt
//
// Each I= entry requires 10,000 inner-loop iterations (INNER_LOOP_MAX=10000),
// NOT a single encryption. The file records the state BEFORE the inner loop
// (KEY, PT/CT) and the FINAL output AFTER 10000 iterations (CT/PT).
//
// §floppy1/ecb_e_m.c: implements the inner loop (INNER_LOOP_MAX=10000)
// §floppy1/serpent-api.h: OUTER_LOOP_MAX=400, INNER_LOOP_MAX=10000
//
// Key update formula (from ecb_e_m.c, verified against ecb_e_m.txt entries):
//   concat = CT_9999 || CT_9998  (32 bytes — LAST output first!)
//   suffix = FIRST keySize/8 bytes of concat
//   KEY[i+1] = KEY[i] XOR suffix
//   (for 128-bit: suffix = CT_9999               = first 16 bytes)
//   (for 192-bit: suffix = CT_9999 || CT_9998[0..7] = first 24 bytes)
//   (for 256-bit: suffix = CT_9999 || CT_9998    = all  32 bytes)

import { describe, it, expect, beforeAll } from 'vitest';
import { Serpent } from '../../src/serpent';
import {
	readVector, hex2bytes, bytes2hex, padKey,
	parseMcEcbEncrypt, parseMcEcbDecrypt,
	McEcbVector,
} from '../helpers/vectors';

const INNER_LOOP = 10000;

// ─────────────────────────────────────────────────────────────────────────────
// Inner loop helpers
// ─────────────────────────────────────────────────────────────────────────────

function runEcbEncryptInnerLoop(
	serpent: Serpent,
	key: Uint8Array,
	initPt: Uint8Array
): { ct9998: Uint8Array; ct9999: Uint8Array } {
	let pt = new Uint8Array(initPt);
	let ct9998 = new Uint8Array(16);
	let ct9999 = new Uint8Array(16);
	for (let j = 0; j < INNER_LOOP; j++) {
		const ct = serpent.encrypt(key, pt);
		if (j === INNER_LOOP - 2) ct9998 = new Uint8Array(ct);
		ct9999 = ct;
		pt = ct; // PT_{j+1} = CT_j
	}
	return { ct9998, ct9999 };
}

function runEcbDecryptInnerLoop(
	serpent: Serpent,
	key: Uint8Array,
	initCt: Uint8Array
): { pt9998: Uint8Array; pt9999: Uint8Array } {
	let ct = new Uint8Array(initCt);
	let pt9998 = new Uint8Array(16);
	let pt9999 = new Uint8Array(16);
	for (let j = 0; j < INNER_LOOP; j++) {
		const pt = serpent.decrypt(key, ct);
		if (j === INNER_LOOP - 2) pt9998 = new Uint8Array(pt);
		pt9999 = pt;
		ct = pt; // CT_{j+1} = PT_j (next input = previous output)
	}
	return { pt9998, pt9999 };
}

function mcKeyUpdate(keysize: number, currentKey: Uint8Array, ct9998: Uint8Array, ct9999: Uint8Array): Uint8Array {
	// AES submission format: concat = CT_9999 (last) || CT_9998 (second-to-last)
	// Take FIRST keyBytes bytes as XOR suffix.
	// Verified empirically: I=0 all-zero 192-bit key, CT_9999 starts I=1 KEY.
	const concat = new Uint8Array(32);
	concat.set(ct9999, 0);   // last output first
	concat.set(ct9998, 16);  // second-to-last second
	const keyBytes = keysize / 8;
	const suffix = concat.slice(0, keyBytes); // first keyBytes of concat
	const newKey = new Uint8Array(keyBytes);
	for (let i = 0; i < keyBytes; i++) newKey[i] = currentKey[i] ^ suffix[i];
	return newKey;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test data
// ─────────────────────────────────────────────────────────────────────────────

let ecbEmVectors: McEcbVector[];
let ecbDmVectors: McEcbVector[];

beforeAll(() => {
	ecbEmVectors = parseMcEcbEncrypt(readVector('ecb_e_m.txt'));
	ecbDmVectors = parseMcEcbDecrypt(readVector('ecb_d_m.txt'));
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. ECB Monte Carlo Encrypt
// ─────────────────────────────────────────────────────────────────────────────

describe('AES Monte Carlo ECB: ecb_e_m.txt', () => {
	it('parses 1200 vectors (400 per key size)', () => {
		expect(ecbEmVectors.length).toBe(1200);
	});

	it('all vectors pass (10000-iteration inner loop)', () => {
		const s = new Serpent();
		for (const v of ecbEmVectors) {
			const key = padKey(v.key, v.keysize);
			const pt  = hex2bytes(v.pt);
			const { ct9999 } = runEcbEncryptInnerLoop(s, key, pt);
			expect(bytes2hex(ct9999)).toEqual(v.ct);
		}
	});

	it('chain continuity: KEY[i+1] derived correctly from CT_9998/CT_9999', () => {
		const s = new Serpent();
		for (const ks of [128, 192, 256]) {
			const group = ecbEmVectors.filter(v => v.keysize === ks);
			for (let i = 0; i + 1 < group.length; i++) {
				const cur  = group[i];
				const next = group[i + 1];
				const key = padKey(cur.key, ks);
				const pt  = hex2bytes(cur.pt);
				const { ct9998, ct9999 } = runEcbEncryptInnerLoop(s, key, pt);
				const expectedNextKey = mcKeyUpdate(ks, key, ct9998, ct9999);
				// Verify next entry's KEY matches the key update rule
				expect(bytes2hex(expectedNextKey)).toEqual(next.key.slice(0, ks / 4));
				// Verify next entry's PT = CT_9999
				expect(bytes2hex(ct9999)).toEqual(next.pt);
			}
		}
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. ECB Monte Carlo Decrypt
// ─────────────────────────────────────────────────────────────────────────────

describe('AES Monte Carlo ECB: ecb_d_m.txt', () => {
	it('parses 1200 vectors', () => {
		expect(ecbDmVectors.length).toBe(1200);
	});

	it('all vectors pass (10000-iteration inner loop)', () => {
		const s = new Serpent();
		for (const v of ecbDmVectors) {
			const key = padKey(v.key, v.keysize);
			const ct  = hex2bytes(v.ct);
			const { pt9999 } = runEcbDecryptInnerLoop(s, key, ct);
			expect(bytes2hex(pt9999)).toEqual(v.pt);
		}
	});
});
