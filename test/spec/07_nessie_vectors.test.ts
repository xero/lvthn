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
// Full NESSIE Serpent-256-128 vector suite (1284 vectors)
//
// Vector source: Serpent-256-128.verified.test-vectors.txt
// @see https://www.cosic.esat.kuleuven.be/nessie/testvectors/
// (also mirrored at biham.cs.technion.ac.il/Reports/Serpent)
//
// Preprocessing applied per test/helpers/nessie.ts:
//   - Key:        reverse all bytes (NESSIE big-endian → leviathan AES-submission)
//   - Plaintext:  reverse all bytes
//   - Ciphertext: reverse all bytes
//
// Run AFTER 06_nessie_helpers.test.ts passes — that file verifies the
// preprocessing logic in isolation.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
	prepareNessieKey,
	prepareNessiePlaintext,
	prepareNessieCiphertext,
	parseNessieVectors,
} from '../helpers/nessie';
import { Serpent } from '../../src/serpent';
import { Convert } from '../../src/base';

function hex(bytes: Uint8Array): string {
	return Convert.bin2hex(bytes).toUpperCase();
}

// ---------------------------------------------------------------------------
// Load and parse once for all tests
// ---------------------------------------------------------------------------

const VECTORS_DIR = resolve(__dirname, '../vectors');
const text = readFileSync(
	resolve(VECTORS_DIR, 'Serpent-256-128.verified.test-vectors.txt'),
	'utf8'
);
const vectors = parseNessieVectors(text);
const s = new Serpent();

// ---------------------------------------------------------------------------
// Encrypt: for every vector, encrypt(plain) should equal cipher
// ---------------------------------------------------------------------------

describe('NESSIE Serpent-256-128 — encrypt (all 1284 vectors)', () => {
	for (const v of vectors) {
		it(`${v.set}, v#${v.num} — encrypt`, () => {
			const key    = prepareNessieKey(v.key);
			const pt     = prepareNessiePlaintext(v.plain);
			const expCT  = prepareNessieCiphertext(v.cipher);
			expect(hex(s.encrypt(key, pt))).toBe(hex(expCT));
		});
	}
});

// ---------------------------------------------------------------------------
// Decrypt: for every vector, decrypt(cipher) should equal plain
// ---------------------------------------------------------------------------

describe('NESSIE Serpent-256-128 — decrypt (all 1284 vectors)', () => {
	for (const v of vectors) {
		it(`${v.set}, v#${v.num} — decrypt`, () => {
			const key    = prepareNessieKey(v.key);
			const ct     = prepareNessieCiphertext(v.cipher);
			const expPT  = prepareNessiePlaintext(v.plain);
			expect(hex(s.decrypt(key, ct))).toBe(hex(expPT));
		});
	}
});
