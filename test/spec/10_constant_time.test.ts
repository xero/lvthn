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
// Tests for constantTimeEqual
// Verifies correctness of the XOR-accumulate constant-time byte comparison
// utility added in Phase 7 of the leviathan audit.
//
// Timing smoke test at the bottom logs durations but does NOT assert on them.
// JavaScript timing is too noisy for reliable timing assertions; the test exists
// to make the timing behaviour visible in CI output.

import { describe, it, expect } from 'vitest';
import { constantTimeEqual } from '../../src/base';

describe('constantTimeEqual', () => {

	// ---------------------------------------------------------------------------
	// Basic correctness
	// ---------------------------------------------------------------------------

	it('equal arrays of length 1 return true', () => {
		expect(constantTimeEqual(new Uint8Array([0x42]), new Uint8Array([0x42]))).toBe(true);
	});

	it('different arrays of same length return false', () => {
		expect(constantTimeEqual(new Uint8Array([0x01]), new Uint8Array([0x02]))).toBe(false);
	});

	it('different arrays of different length return false', () => {
		expect(constantTimeEqual(new Uint8Array([0x01, 0x02]), new Uint8Array([0x01]))).toBe(false);
	});

	it('empty arrays return true', () => {
		expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// All-zero arrays of standard cryptographic sizes
	// ---------------------------------------------------------------------------

	it('all-zero array length 1 equals itself', () => {
		expect(constantTimeEqual(new Uint8Array(1), new Uint8Array(1))).toBe(true);
	});

	it('all-zero array length 16 equals itself', () => {
		expect(constantTimeEqual(new Uint8Array(16), new Uint8Array(16))).toBe(true);
	});

	it('all-zero array length 32 equals itself', () => {
		expect(constantTimeEqual(new Uint8Array(32), new Uint8Array(32))).toBe(true);
	});

	// ---------------------------------------------------------------------------
	// Single-byte difference — accumulator must catch differences at any position
	// ---------------------------------------------------------------------------

	it('single-byte difference at position 0 returns false', () => {
		const a = new Uint8Array(32);
		const b = new Uint8Array(32);
		b[0] = 0x01;
		expect(constantTimeEqual(a, b)).toBe(false);
	});

	it('single-byte difference at middle position returns false', () => {
		const a = new Uint8Array(32);
		const b = new Uint8Array(32);
		b[15] = 0x01;
		expect(constantTimeEqual(a, b)).toBe(false);
	});

	it('single-byte difference at last position returns false', () => {
		const a = new Uint8Array(32);
		const b = new Uint8Array(32);
		b[31] = 0x01;
		expect(constantTimeEqual(a, b)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Round-trip on non-trivial data
	// ---------------------------------------------------------------------------

	it('identical non-trivial 32-byte arrays return true', () => {
		const a = new Uint8Array(32);
		for (let i = 0; i < 32; i++) a[i] = (i * 37 + 13) & 0xff;
		const b = new Uint8Array(a);
		expect(constantTimeEqual(a, b)).toBe(true);
	});

	it('non-trivial arrays differing in one byte return false', () => {
		const a = new Uint8Array(32);
		for (let i = 0; i < 32; i++) a[i] = (i * 37 + 13) & 0xff;
		const b = new Uint8Array(a);
		b[7] ^= 0xff;
		expect(constantTimeEqual(a, b)).toBe(false);
	});

	// ---------------------------------------------------------------------------
	// Timing smoke test
	//
	// Logs the wall-clock duration of 1000 equal-array comparisons vs 1000
	// comparisons where arrays differ at byte 0.  Does NOT assert on timing —
	// JIT non-determinism makes reliable timing assertions impossible in JS.
	// The purpose is to make the timing profile visible in CI output so a human
	// reviewer can spot gross regressions (e.g. an accidental early-return).
	// ---------------------------------------------------------------------------

	it('timing smoke: equal vs early-differing arrays (log only, no assertion)', () => {
		const SIZE = 32;
		const ITER = 1000;

		const eq_a = new Uint8Array(SIZE).fill(0xAB);
		const eq_b = new Uint8Array(SIZE).fill(0xAB);

		const diff_a = new Uint8Array(SIZE).fill(0xAB);
		const diff_b = new Uint8Array(SIZE).fill(0xAB);
		diff_b[0] = 0x00;  // differs at position 0 — would exit early in a naive loop

		const t0 = performance.now();
		for (let i = 0; i < ITER; i++) constantTimeEqual(eq_a, eq_b);
		const equalMs = performance.now() - t0;

		const t1 = performance.now();
		for (let i = 0; i < ITER; i++) constantTimeEqual(diff_a, diff_b);
		const diffMs = performance.now() - t1;

		// Log for CI visibility — not asserted
		console.log(`constantTimeEqual timing smoke (${ITER} iterations, ${SIZE} bytes):`);
		console.log(`  equal arrays:     ${equalMs.toFixed(3)} ms`);
		console.log(`  diff at byte 0:   ${diffMs.toFixed(3)} ms`);

		// Only assertion: the function returns the correct answers
		expect(constantTimeEqual(eq_a, eq_b)).toBe(true);
		expect(constantTimeEqual(diff_a, diff_b)).toBe(false);
	});

});
