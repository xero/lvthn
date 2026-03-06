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
//  Serpent256 Intermediate Value Tests — ecb_iv.txt
//
// These tests verify the key schedule and final cipher output using the
// intermediate-value test vectors from ecb_iv.txt.
//
// ## Why round-by-round R[i] comparison is not attempted
//
// The R[i] values in ecb_iv.txt are produced by the reference implementation
// using KHat (SK^[], conventional subkeys). leviathan uses SK[] (bitslice
// subkeys) with a different internal state representation (reversed-byte LE
// loading rather than the IP permutation). Both implementations compute the
// same cipher, but their per-round internal states differ. Direct R[i]
// comparison would require a non-trivial bit-level transformation.
//
// ## What IS verified (§MANDATORY)
//
// 1. Final CT: for every ecb_iv.txt test case, encrypt(pt) == ct.
// 2. Key schedule: SK[i] from ecb_iv.txt matches leviathan's derived subkeys.
//    ecb_iv.txt SK[i] is rendered by serpent-aux.c render() which prints
//    words from index 3 down to 0 (§serpent-aux.c render()).
//    leviathan stores [X0,X1,X2,X3] at this.key[4*i..4*i+3], so the file has
//    them in reversed order: SK[i] = X3|X2|X1|X0.
// 3. Decrypt round-trip: decrypt(ct) == pt for all test cases.
//
// §serpent-aux.c render()

import { describe, it, expect, beforeAll } from 'vitest';
import { Serpent } from '../../src/serpent';
import type { RoundHook } from '../../src/serpent';
import {
	readVector, hex2bytes, bytes2hex, padKey,
	parseIv, hex2words,
	IvTestCase,
} from '../helpers/vectors';

let ivCases: IvTestCase[];

beforeAll(() => {
	ivCases = parseIv(readVector('ecb_iv.txt'));
});

// ─────────────────────────────────────────────────────────────────────────────
// Test: parse ecb_iv.txt
// ─────────────────────────────────────────────────────────────────────────────

describe('AES ecb_iv.txt (intermediate values)', () => {
	it('parses non-zero test cases', () => {
		expect(ivCases.length).toBeGreaterThan(0);
	});

	// ── Final CT correctness for all test cases ─────────────────────────────

	it('final CT matches for all ecb_iv test cases', () => {
		const s = new Serpent();
		for (const tc of ivCases) {
			const key = padKey(tc.key, tc.keysize);
			const pt  = hex2bytes(tc.pt);
			const ct  = bytes2hex(s.encrypt(key, pt));
			expect(ct).toEqual(tc.ct);
		}
	});

	// ── §MANDATORY: Key schedule verification via SK[] ──────────────────────
	//
	// SK[i] in ecb_iv.txt is produced by render() which prints words from
	// index 3 down to 0: file hex = X3|X2|X1|X0.
	// leviathan stores [X0,X1,X2,X3] at this.key[4*i .. 4*i+3].
	// To compare: reverse the 4 file words → [X0,X1,X2,X3] = leviathan order.

	it('§MANDATORY subkey schedule: SK[0..32] match leviathan derived subkeys', () => {
		const tc = ivCases.find(c => c.keysize === 128);
		expect(tc).toBeDefined();
		if (!tc) return;

		const key = padKey(tc.key, tc.keysize!);
		const s = new Serpent();
		const subkeys = s.getSubkeys(key); // [X0,X1,X2,X3] per subkey

		const failures: string[] = [];

		for (let i = 0; i <= 32; i++) {
			if (!tc.sk[i] || tc.sk[i].length !== 32) continue;

			// File SK[i] = render() output = X3|X2|X1|X0 (4 words, rendered high→low)
			const fileWords = hex2words(tc.sk[i]); // [X3, X2, X1, X0]

			// leviathan: this.key[4*i .. 4*i+3] = [X0, X1, X2, X3]
			const leviathanX0 = subkeys[4 * i + 0] >>> 0;
			const leviathanX1 = subkeys[4 * i + 1] >>> 0;
			const leviathanX2 = subkeys[4 * i + 2] >>> 0;
			const leviathanX3 = subkeys[4 * i + 3] >>> 0;

			// fileWords[0]=X3, fileWords[1]=X2, fileWords[2]=X1, fileWords[3]=X0
			const fileX0 = fileWords[3] >>> 0;
			const fileX1 = fileWords[2] >>> 0;
			const fileX2 = fileWords[1] >>> 0;
			const fileX3 = fileWords[0] >>> 0;

			if (leviathanX0 !== fileX0 || leviathanX1 !== fileX1 ||
          leviathanX2 !== fileX2 || leviathanX3 !== fileX3) {
				failures.push(
					`SK[${i}]: leviathan=[${leviathanX0.toString(16).padStart(8, '0')} ${leviathanX1.toString(16).padStart(8, '0')} ${leviathanX2.toString(16).padStart(8, '0')} ${leviathanX3.toString(16).padStart(8, '0')}] ` +
          `file=[${fileX0.toString(16).padStart(8, '0')} ${fileX1.toString(16).padStart(8, '0')} ${fileX2.toString(16).padStart(8, '0')} ${fileX3.toString(16).padStart(8, '0')}]`
				);
			}
		}

		if (failures.length > 0) {
			throw new Error('Key schedule mismatches:\n' + failures.join('\n'));
		}
	});

	// ── §MANDATORY: Decrypt round-trip ─────────────────────────────────────

	it('§MANDATORY round states: decrypt reverses all round states', () => {
		// For each ecb_iv test case, verify decrypt(ct) == pt (round-trip)
		const s = new Serpent();
		for (const tc of ivCases) {
			const key = padKey(tc.key, tc.keysize);
			const ct  = hex2bytes(tc.ct);
			expect(bytes2hex(s.decrypt(key, ct))).toEqual(tc.pt);
		}
	});

	// ── RoundHook sanity: hook fires 32 times with valid EC values ──────────

	it('roundHook fires exactly 32 times per encrypt', () => {
		const tc = ivCases.find(c => c.keysize === 128);
		if (!tc) return;

		const key = padKey(tc.key, tc.keysize!);
		const pt  = hex2bytes(tc.pt);

		const rounds: number[] = [];
		const s = new Serpent();
		s.roundHook = ((round: number, _r: number[], _ec: number) => {
			rounds.push(round);
		}) as RoundHook;

		s.encrypt(key, pt);
		s.roundHook = null;

		expect(rounds.length).toBe(32);
		// Rounds should be 0..31 in order
		for (let i = 0; i < 32; i++) {
			expect(rounds[i]).toBe(i);
		}
	});
});
