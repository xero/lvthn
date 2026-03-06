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
// Tests for Argon2id — memory-hard password hashing and key derivation
//
// These tests are slower than other leviathan tests due to the memory-hard
// computation — each hash allocates 19+ MiB and performs multiple passes.
// The 10-minute test timeout in vitest.config.ts covers the full suite.
//
// Underlying package: argon2id@1.0.1 (OpenPGP.js team, RFC 9106 compliant)

import { describe, it, expect } from 'vitest';
import {
	Argon2id,
	ARGON2ID_INTERACTIVE,
	ARGON2ID_SENSITIVE,
	ARGON2ID_DERIVE,
	type Argon2idParams,
} from '../../src/argon2id';
import { Serpent_CBC_PKCS7 } from '../../src/serpent';
import { Convert } from '../../src/base';

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

describe('Argon2id — parameter validation', () => {

	it('rejects memoryCost < 8', async () => {
		const argon2 = new Argon2id();
		const badParams: Argon2idParams = { ...ARGON2ID_INTERACTIVE, memoryCost: 4 };
		await expect(argon2.hash('password', undefined, badParams))
			.rejects.toThrow('memoryCost');
	});

	it('rejects timeCost < 1', async () => {
		const argon2 = new Argon2id();
		const badParams: Argon2idParams = { ...ARGON2ID_INTERACTIVE, timeCost: 0 };
		await expect(argon2.hash('password', undefined, badParams))
			.rejects.toThrow('timeCost');
	});

	it('rejects parallelism < 1', async () => {
		const argon2 = new Argon2id();
		const badParams: Argon2idParams = { ...ARGON2ID_INTERACTIVE, parallelism: 0 };
		await expect(argon2.hash('password', undefined, badParams))
			.rejects.toThrow('parallelism');
	});

	it('rejects hashLength < 4', async () => {
		const argon2 = new Argon2id();
		const badParams: Argon2idParams = { ...ARGON2ID_INTERACTIVE, hashLength: 3 };
		await expect(argon2.hash('password', undefined, badParams))
			.rejects.toThrow('hashLength');
	});

	it('rejects saltLength < 8', async () => {
		const argon2 = new Argon2id();
		const badParams: Argon2idParams = { ...ARGON2ID_INTERACTIVE, saltLength: 4 };
		// must also provide a salt to bypass the auto-generation length, OR test
		// that providing a short salt is rejected
		const shortSalt = new Uint8Array(4);
		await expect(argon2.hash('password', shortSalt, badParams))
			.rejects.toThrow('saltLength');
	});

});

// ---------------------------------------------------------------------------
// hash()
// ---------------------------------------------------------------------------

describe('Argon2id — hash()', () => {

	it('returns a Uint8Array of the correct hashLength', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32);
		const result = await argon2.hash('test', salt);
		expect(result.hash).toBeInstanceOf(Uint8Array);
		expect(result.hash.length).toBe(ARGON2ID_INTERACTIVE.hashLength);
	});

	it('returns a salt of the correct saltLength when none is provided', async () => {
		const argon2 = new Argon2id();
		const result = await argon2.hash('test');
		expect(result.salt).toBeInstanceOf(Uint8Array);
		expect(result.salt.length).toBe(ARGON2ID_INTERACTIVE.saltLength);
	});

	it('same password + same salt + same params → same hash (deterministic)', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0xab);
		const r1 = await argon2.hash('hello world', salt);
		const r2 = await argon2.hash('hello world', salt);
		expect(Convert.bin2hex(r1.hash)).toBe(Convert.bin2hex(r2.hash));
	});

	it('different salt → different hash', async () => {
		const argon2 = new Argon2id();
		const salt1 = new Uint8Array(32).fill(0x01);
		const salt2 = new Uint8Array(32).fill(0x02);
		const r1 = await argon2.hash('hello world', salt1);
		const r2 = await argon2.hash('hello world', salt2);
		expect(Convert.bin2hex(r1.hash)).not.toBe(Convert.bin2hex(r2.hash));
	});

	it('different password → different hash', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0xcd);
		const r1 = await argon2.hash('password-one', salt);
		const r2 = await argon2.hash('password-two', salt);
		expect(Convert.bin2hex(r1.hash)).not.toBe(Convert.bin2hex(r2.hash));
	});

	it('string and Uint8Array passwords produce the same hash for the same UTF-8 bytes', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0xee);
		const passwordStr = 'correct horse battery staple';
		const passwordBytes = new TextEncoder().encode(passwordStr);
		const r1 = await argon2.hash(passwordStr, salt);
		const r2 = await argon2.hash(passwordBytes, salt);
		expect(Convert.bin2hex(r1.hash)).toBe(Convert.bin2hex(r2.hash));
	});

	it('ARGON2ID_INTERACTIVE preset produces 32-byte output', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32);
		const result = await argon2.hash('test', salt, ARGON2ID_INTERACTIVE);
		expect(result.hash.length).toBe(32);
	});

	it('ARGON2ID_DERIVE preset produces 32-byte output', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32);
		const result = await argon2.hash('test', salt, ARGON2ID_DERIVE);
		expect(result.hash.length).toBe(32);
	});

	it('ARGON2ID_SENSITIVE preset produces 32-byte output', async () => {
		// Note: ARGON2ID_SENSITIVE uses 64 MiB RAM and 3 passes — this test is slower
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32);
		const result = await argon2.hash('test', salt, ARGON2ID_SENSITIVE);
		expect(result.hash.length).toBe(32);
	});

});

// ---------------------------------------------------------------------------
// verify()
// ---------------------------------------------------------------------------

describe('Argon2id — verify()', () => {

	it('correct password → returns true', async () => {
		const argon2 = new Argon2id();
		const { hash, salt, params } = await argon2.hash('my-secret-password');
		const ok = await argon2.verify('my-secret-password', hash, salt, params);
		expect(ok).toBe(true);
	});

	it('wrong password → returns false', async () => {
		const argon2 = new Argon2id();
		const { hash, salt, params } = await argon2.hash('correct-password');
		const ok = await argon2.verify('wrong-password', hash, salt, params);
		expect(ok).toBe(false);
	});

	it('correct password + wrong salt → returns false', async () => {
		const argon2 = new Argon2id();
		const { hash, params } = await argon2.hash('password', new Uint8Array(32).fill(0x01));
		const wrongSalt = new Uint8Array(32).fill(0x02);
		const ok = await argon2.verify('password', hash, wrongSalt, params);
		expect(ok).toBe(false);
	});

	it('correct password + wrong params → returns false', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0x42);
		const { hash } = await argon2.hash('password', salt, ARGON2ID_INTERACTIVE);
		// Different timeCost produces a different hash
		const altParams: Argon2idParams = { ...ARGON2ID_INTERACTIVE, timeCost: 3 };
		const ok = await argon2.verify('password', hash, salt, altParams);
		expect(ok).toBe(false);
	});

});

// ---------------------------------------------------------------------------
// deriveKey()
// ---------------------------------------------------------------------------

describe('Argon2id — deriveKey()', () => {

	it('returns key of 16 bytes when keyLength=16', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32);
		const { key } = await argon2.deriveKey('passphrase', salt, 16);
		expect(key).toBeInstanceOf(Uint8Array);
		expect(key.length).toBe(16);
	});

	it('returns key of 24 bytes when keyLength=24', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32);
		const { key } = await argon2.deriveKey('passphrase', salt, 24);
		expect(key.length).toBe(24);
	});

	it('returns key of 32 bytes (default)', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32);
		const { key } = await argon2.deriveKey('passphrase', salt);
		expect(key.length).toBe(32);
	});

	it('same passphrase + same salt → same key (deterministic)', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0x77);
		const r1 = await argon2.deriveKey('my passphrase', salt);
		const r2 = await argon2.deriveKey('my passphrase', salt);
		expect(Convert.bin2hex(r1.key)).toBe(Convert.bin2hex(r2.key));
	});

	it('different passphrases → different keys', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0x55);
		const r1 = await argon2.deriveKey('passphrase-alpha', salt);
		const r2 = await argon2.deriveKey('passphrase-beta', salt);
		expect(Convert.bin2hex(r1.key)).not.toBe(Convert.bin2hex(r2.key));
	});

	it('derived key is valid Serpent-256 key material — encrypt/decrypt round-trip', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0x33);
		const { key } = await argon2.deriveKey('serpent key derivation test', salt, 32);

		const cipher = new Serpent_CBC_PKCS7();
		const iv = new Uint8Array(16).fill(0x11);
		const plaintext = Convert.str2bin('Hello, Argon2id!');

		const ciphertext = cipher.encrypt(key, plaintext, iv);
		const recovered  = cipher.decrypt(key, ciphertext, iv);

		expect(Convert.bin2str(recovered)).toBe('Hello, Argon2id!');
	});

	it('derived 16-byte key is valid Serpent-128 key material', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0x44);
		const { key } = await argon2.deriveKey('128-bit test', salt, 16);

		const cipher = new Serpent_CBC_PKCS7();
		const iv = new Uint8Array(16);
		const plaintext = Convert.str2bin('Serpent-128 test');

		const ciphertext = cipher.encrypt(key, plaintext, iv);
		const recovered  = cipher.decrypt(key, ciphertext, iv);

		expect(Convert.bin2str(recovered)).toBe('Serpent-128 test');
	});

});

// ---------------------------------------------------------------------------
// Known-value test vector
//
// Fixed input hashed against argon2id@1.0.1 with ARGON2ID_INTERACTIVE params.
// Generated once; hardcoded to catch silent regressions if the underlying
// package ever changes its output for the same inputs.
//
// To regenerate: remove the expected value, run the test with console.log
// to print result.hash, then hardcode the output here.
// ---------------------------------------------------------------------------

describe('Argon2id — known-value test vector', () => {

	it('fixed input with ARGON2ID_INTERACTIVE produces known hash (argon2id@1.0.1)', async () => {
		const argon2 = new Argon2id();

		// Fixed inputs: well-known test string, all-zero salt, INTERACTIVE params
		const password = new TextEncoder().encode('leviathan-test-vector');
		const salt = new Uint8Array(32);  // all zeros for reproducibility

		const result = await argon2.hash(password, salt, ARGON2ID_INTERACTIVE);

		// Known value generated against argon2id@1.0.1
		// params: memoryCost=19456, timeCost=2, parallelism=1, hashLength=32
		const expected = '10d5c29010a4c2b264437392babb0bc21b3d3292459c9898572c500b590bdf14';

		expect(Convert.bin2hex(result.hash)).toBe(expected);
	});

});

// ---------------------------------------------------------------------------
// Constant-time verification smoke test
//
// Logs the wall-clock duration for correct vs incorrect password verification.
// Does NOT assert on timing — JavaScript timing is too noisy for reliable
// timing assertions. The test exists to make timing behaviour visible in CI.
// ---------------------------------------------------------------------------

describe('Argon2id — constant-time verification smoke test', () => {

	it('timing smoke: correct vs wrong password (log only, no assertion)', async () => {
		const argon2 = new Argon2id();
		const salt = new Uint8Array(32).fill(0xfe);
		const { hash, params } = await argon2.hash('timing-test-correct', salt);

		const t0 = performance.now();
		const correct = await argon2.verify('timing-test-correct', hash, salt, params);
		const correctMs = performance.now() - t0;

		const t1 = performance.now();
		const wrong = await argon2.verify('timing-test-WRONG', hash, salt, params);
		const wrongMs = performance.now() - t1;

		console.log('Argon2id constant-time verification smoke:');
		console.log(`  correct password: ${correctMs.toFixed(1)} ms`);
		console.log(`  wrong password:   ${wrongMs.toFixed(1)} ms`);

		// Only assertion: correctness
		expect(correct).toBe(true);
		expect(wrong).toBe(false);
	});

});
