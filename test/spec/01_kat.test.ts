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
//            ▀████▄   ▄██▄                   +---------------+
//              ▐████   ▐███                  |   TEST SPEC   |
//       ▄▄██████████    ▐███         ▄▄      +---------------+
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
// Known Answer Tests (KAT)
// Sources: ecb_vt.txt (variable plaintext), ecb_vk.txt (variable key),
//          ecb_tbl.txt (S-box entry tests)
// AES candidate submission by Ross Anderson, Eli Biham, Lars Knudsen.

import { describe, it, expect, beforeAll } from 'vitest';
import { Serpent } from '../../src/serpent';
import {
	readVector, hex2bytes, bytes2hex, padKey,
	parseVt, parseVk, parseTbl,
	KatVector,
} from '../helpers/vectors';

// ─────────────────────────────────────────────────────────────────────────────
// Test data (loaded once)
// ─────────────────────────────────────────────────────────────────────────────

let vtVectors:  KatVector[];
let vkVectors:  KatVector[];
let tblVectors: KatVector[];

beforeAll(() => {
	vtVectors  = parseVt(readVector('ecb_vt.txt'));
	vkVectors  = parseVk(readVector('ecb_vk.txt'));
	tblVectors = parseTbl(readVector('ecb_tbl.txt'));
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. ecb_vt.txt — Variable Plaintext KAT
// ─────────────────────────────────────────────────────────────────────────────

describe('AES KAT: ecb_vt.txt (variable plaintext)', () => {
	const s = new Serpent();

	it('parses non-zero vectors', () => {
		expect(vtVectors.length).toBeGreaterThan(0);
	});

	it('encrypt: all vectors', () => {
		for (const v of vtVectors) {
			const key = padKey(v.key, v.keysize);
			const pt  = hex2bytes(v.pt);
			expect(bytes2hex(s.encrypt(key, pt))).toEqual(v.ct);
		}
	});

	it('decrypt: all vectors', () => {
		for (const v of vtVectors) {
			const key = padKey(v.key, v.keysize);
			const ct  = hex2bytes(v.ct);
			expect(bytes2hex(s.decrypt(key, ct))).toEqual(v.pt);
		}
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. ecb_vk.txt — Variable Key KAT
// ─────────────────────────────────────────────────────────────────────────────

describe('AES KAT: ecb_vk.txt (variable key)', () => {
	const s = new Serpent();

	it('parses non-zero vectors', () => {
		expect(vkVectors.length).toBeGreaterThan(0);
	});

	it('encrypt: all vectors', () => {
		for (const v of vkVectors) {
			const key = padKey(v.key, v.keysize);
			const pt  = hex2bytes(v.pt);
			expect(bytes2hex(s.encrypt(key, pt))).toEqual(v.ct);
		}
	});

	it('decrypt: all vectors', () => {
		for (const v of vkVectors) {
			const key = padKey(v.key, v.keysize);
			const ct  = hex2bytes(v.ct);
			expect(bytes2hex(s.decrypt(key, ct))).toEqual(v.pt);
		}
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. ecb_tbl.txt — S-Box Entry Tests
// ─────────────────────────────────────────────────────────────────────────────

describe('AES KAT: ecb_tbl.txt (S-box entry tests)', () => {
	const s = new Serpent();

	it('parses non-zero vectors', () => {
		expect(tblVectors.length).toBeGreaterThan(0);
	});

	it('encrypt: all S-box entry vectors', () => {
		for (const v of tblVectors) {
			const key = padKey(v.key, v.keysize);
			const pt  = hex2bytes(v.pt);
			expect(bytes2hex(s.encrypt(key, pt))).toEqual(v.ct);
		}
	});

	it('decrypt: all S-box entry vectors', () => {
		for (const v of tblVectors) {
			const key = padKey(v.key, v.keysize);
			const ct  = hex2bytes(v.ct);
			expect(bytes2hex(s.decrypt(key, ct))).toEqual(v.pt);
		}
	});
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Encrypt/decrypt round-trips
// ─────────────────────────────────────────────────────────────────────────────

describe('Round-trip encrypt/decrypt', () => {
	const s = new Serpent();

	const cases = [
		{ label: '128-bit key, zero block',    key: new Uint8Array(16), pt: new Uint8Array(16) },
		{ label: '192-bit key, zero block',    key: new Uint8Array(24), pt: new Uint8Array(16) },
		{ label: '256-bit key, zero block',    key: new Uint8Array(32), pt: new Uint8Array(16) },
		{ label: '128-bit key, all-FF block',  key: new Uint8Array(16).fill(0xff), pt: new Uint8Array(16).fill(0xff) },
		{ label: '256-bit key, all-FF block',  key: new Uint8Array(32).fill(0xff), pt: new Uint8Array(16).fill(0xff) },
	];

	for (const c of cases) {
		it(`round-trip: ${c.label}`, () => {
			const ct = s.encrypt(c.key, c.pt);
			const pt2 = s.decrypt(c.key, ct);
			expect(bytes2hex(pt2)).toEqual(bytes2hex(c.pt));
		});
	}
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Serpent.selftest()
// ─────────────────────────────────────────────────────────────────────────────

describe('Serpent.selftest()', () => {
	it('returns true', () => {
		const s = new Serpent();
		expect(s.selftest()).toBe(true);
	});
});
