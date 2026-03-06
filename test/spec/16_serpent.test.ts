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
// Serpent256 Monte Carlo Tests
// Vectors:  AES submission, Ross Anderson et al.
// The Monte Carlo tests (10 000 rounds each) are intentionally slow.
// A per-test timeout of 60 s is set to avoid flaky failures on slower CI
// machines; the overall suite timeout in vitest.config.ts covers the rest.

import { describe, it, expect } from 'vitest';
import { Serpent, Serpent_CBC_PKCS7 } from '../../src/serpent';
import { Convert } from '../../src/base';
import { vector, vectorMonteCarloEncrypt, vectorMonteCarloDecrypt, vectorCBC_PKCS7 } from '../vectors/serpent_vectors';

describe('Serpent', () => {
	const serpent = new Serpent();

	describe('encrypt', () => {
		it(`check ${vector.length} test vectors`, () => {
			for (const v of vector) {
				const key = Convert.hex2bin(v.key);
				const pt  = Convert.hex2bin(v.pt);
				const ct  = Convert.hex2bin(v.ct);
				expect(serpent.encrypt(key, pt)).toEqual(ct);
			}
		});
	});

	describe('decrypt', () => {
		it(`check ${vector.length} test vectors`, () => {
			for (const v of vector) {
				const key = Convert.hex2bin(v.key);
				const pt  = Convert.hex2bin(v.pt);
				const ct  = Convert.hex2bin(v.ct);
				expect(serpent.decrypt(key, ct)).toEqual(pt);
			}
		});
	});

	describe('encrypt - Monte Carlo 10000 rounds', () => {
		it(`check ${vectorMonteCarloEncrypt.length} test vectors`, { timeout: 60000 }, () => {
			for (const v of vectorMonteCarloEncrypt) {
				const key = Convert.hex2bin(v.key);
				let pt    = Convert.hex2bin(v.pt);
				const ct  = Convert.hex2bin(v.ct);
				for (let n = 0; n < 10000; n++) {
					pt = serpent.encrypt(key, pt);
				}
				expect(pt).toEqual(ct);
			}
		});
	});

	describe('decrypt - Monte Carlo 10000 rounds', () => {
		it(`check ${vectorMonteCarloDecrypt.length} test vectors`, { timeout: 60000 }, () => {
			for (const v of vectorMonteCarloDecrypt) {
				const key = Convert.hex2bin(v.key);
				const pt  = Convert.hex2bin(v.pt);
				let ct    = Convert.hex2bin(v.ct);
				for (let n = 0; n < 10000; n++) {
					ct = serpent.decrypt(key, ct);
				}
				expect(ct).toEqual(pt);
			}
		});
	});

	describe('CBC-PKCS7', () => {
		it(`check ${vectorCBC_PKCS7.length} test vectors (encrypt → decrypt round-trip)`, () => {
			const serpentCBC = new Serpent_CBC_PKCS7();
			for (const v of vectorCBC_PKCS7) {
				const key = Convert.hex2bin(v.key);
				const pt  = Convert.hex2bin(v.pt);
				const iv  = Convert.hex2bin(v.iv);
				const ct  = serpentCBC.encrypt(key, pt, iv);
				const pt2 = serpentCBC.decrypt(key, ct, iv);
				expect(pt2).toEqual(pt);
			}
		});
	});

	describe('selftest', () => {
		it('selftest passes', () => {
			expect(serpent.selftest()).toBe(true);
		});
	});
});
