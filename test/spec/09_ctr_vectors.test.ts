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

import { describe, it, expect } from 'vitest';
import { Serpent_CTR } from '../../src/serpent';
import { Serpent } from '../../src/serpent';
import { Convert } from '../../src/base';
import { VECTORS } from '../vectors/ctr_vectors';

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function hex(bytes: Uint8Array): string {
	return Convert.bin2hex(bytes).toUpperCase();
}

function h2b(s: string): Uint8Array {
	return Convert.hex2bin(s);
}

// ---------------------------------------------------------------------------
// Helpers: extract a 16-byte block from a hex string
// ---------------------------------------------------------------------------

function block(hexStr: string, n: number): string {
	return hexStr.slice(n * 32, (n + 1) * 32);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Serpent-CTR authoritative vectors', () => {
	const serpentCtr = new Serpent_CTR();

	for (const v of VECTORS) {
		const key = h2b(v.keyHex);
		const iv  = h2b(v.ivHex);
		const pt  = h2b(v.ptHex);
		const ct  = h2b(v.ctHex);

		it(`Case ${v.label} — encrypt`, () => {
			expect(hex(serpentCtr.encrypt(key, pt, iv))).toBe(v.ctHex);
		});

		it(`Case ${v.label} — decrypt`, () => {
			expect(hex(serpentCtr.decrypt(key, ct, iv))).toBe(v.ptHex);
		});

		if (v.blocks >= 3) {
			it(`Case ${v.label} — block boundary: blocks 0/1/2 are distinct (counter increments)`, () => {
				const ctHex = hex(serpentCtr.encrypt(key, pt, iv));
				const b0 = block(ctHex, 0);
				const b1 = block(ctHex, 1);
				const b2 = block(ctHex, 2);
				expect(b0).not.toBe(b1);
				expect(b0).not.toBe(b2);
				expect(b1).not.toBe(b2);
			});
		}
	}

	// -------------------------------------------------------------------------
	// IV independence tests (Cases A and B: all-zero PT)
	// -------------------------------------------------------------------------

	it('Case A — IV independence: different IV produces different ciphertext', () => {
		const key    = h2b(VECTORS[0].keyHex);
		const pt     = h2b(VECTORS[0].ptHex);
		const ivZero = h2b(VECTORS[0].ivHex);                        // all-zero IV
		const ivOther = new Uint8Array(16); ivOther[15] = 0x01;      // IV = 0x00...01
		const ct1 = hex(serpentCtr.encrypt(key, pt, ivZero));
		const ct2 = hex(serpentCtr.encrypt(key, pt, ivOther));
		expect(ct1).not.toBe(ct2);
	});

	it('Case B — IV independence: different IV produces different ciphertext', () => {
		const key     = h2b(VECTORS[1].keyHex);
		const pt      = h2b(VECTORS[1].ptHex);
		const ivZero  = h2b(VECTORS[1].ivHex);
		const ivOther = new Uint8Array(16); ivOther[0] = 0x01;
		const ct1 = hex(serpentCtr.encrypt(key, pt, ivZero));
		const ct2 = hex(serpentCtr.encrypt(key, pt, ivOther));
		expect(ct1).not.toBe(ct2);
	});

	// -------------------------------------------------------------------------
	// Cross-corpus ECB sanity check
	//
	// Ties these CTR tests back to the verified AES-submission ECB corpus.
	// For CTR with all-zero PT, CT == raw keystream.
	// keystream_block_0 = ECB_encrypt(key, counter_0) = ECB_encrypt(key, IV).
	// We verify this against Case A (128-bit key) and Case B (256-bit key).
	// -------------------------------------------------------------------------

	it('Cross-corpus ECB sanity: Case A block 0 CT = ECB_encrypt(all-zero-128-key, all-zero-counter)', () => {
		const s      = new Serpent();
		const key    = h2b(VECTORS[0].keyHex);   // all-zero 128-bit key
		const ctrBlk = new Uint8Array(16);        // all-zero counter (= all-zero IV)
		const ecbKS  = hex(s.encrypt(key, ctrBlk));
		// Case A PT is all-zero, so CT block 0 == keystream block 0 == ECB output
		const caseAblock0 = block(VECTORS[0].ctHex, 0);
		expect(ecbKS).toBe(caseAblock0);         // must be E9BA668276B81896D093A9E67AB12036
	});

	it('Cross-corpus ECB sanity: Case B block 0 CT = ECB_encrypt(all-zero-256-key, all-zero-counter)', () => {
		const s      = new Serpent();
		const key    = h2b(VECTORS[1].keyHex);   // all-zero 256-bit key
		const ctrBlk = new Uint8Array(16);        // all-zero counter
		const ecbKS  = hex(s.encrypt(key, ctrBlk));
		const caseBblock0 = block(VECTORS[1].ctHex, 0);
		expect(ecbKS).toBe(caseBblock0);         // must be 8910494504181950F98DD998A82B6749
	});
});
