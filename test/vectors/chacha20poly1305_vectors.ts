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
// ChaCha20-Poly1305 & XChaCha20-Poly1305 test vectors
//
// Sources:
//   RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols (June 2018)
//   @see https://www.rfc-editor.org/rfc/rfc8439
//   Sections covered: §A.2 (block), §A.3 (Poly1305 MAC), §A.4 (key gen),
//                     §2.8.2 / Appendix A.5 (AEAD)
//
//   XChaCha20-Poly1305 IETF draft (draft-irtf-cfrg-xchacha-03)
//   @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
//   Sections covered: §2.2.1 (HChaCha20), §2.7.1 (XChaCha20-Poly1305 AEAD)
//
// All hex strings are lowercase, no separators.
// Audit status: VERIFIED — per-vector citations in each export below.

// ============================================================
// RFC 8439 §A.2 — ChaCha20 block function
// ============================================================

export interface BlockFunctionVector {
  description: string;
  key:       string; // 32 bytes (64 hex chars)
  nonce:     string; // 12 bytes (24 hex chars)
  counter:   number;
  keystream: string; // 64 bytes (128 hex chars)
}

/** RFC 8439 Appendix A.2 test vectors for the ChaCha20 block function. */
export const chacha20BlockVectors: BlockFunctionVector[] = [
	{
		// RFC 8439 §A.2 Test Vector #1
		description: 'RFC 8439 §A.2.1: all-zero key, all-zero nonce, counter=0',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		nonce: '000000000000000000000000',
		counter: 0,
		keystream:
      '76b8e0ada0f13d90405d6ae55386bd28' +
      'bdd219b8a08ded1aa836efcc8b770dc7' +
      'da41597c5157488d7724e03fb8d84a37' +
      '6a43b8f41518a11cc387b669b2ee6586',
	},
	{
		// RFC 8439 §A.2 Test Vector #2 (counter=1)
		description: 'RFC 8439 §A.2.2: sequential key, non-zero nonce, counter=1',
		key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		nonce: '000000090000004a00000000',
		counter: 1,
		keystream:
      '10f1e7e4d13b5915500fdd1fa32071c4' +
      'c7d1f4c733c068030422aa9ac3d46c4e' +
      'd2826446079faa0914c2d705d98b02a2' +
      'b5129cd1de164eb9cbd083e8a2503c4e',
	},
];

// ============================================================
// RFC 8439 §A.3 — Poly1305 MAC
// ============================================================

export interface Poly1305Vector {
  description: string;
  key:      string;   // 32 bytes (64 hex)
  msg?:     string;   // message as hex (optional if msgText is set)
  msgText?: string;   // message as UTF-8 text (encoded via TextEncoder in tests)
  tag:      string;   // 16 bytes (32 hex)
}

/** RFC 8439 Appendix A.3 test vectors for the Poly1305 MAC. */
export const poly1305Vectors: Poly1305Vector[] = [
	{
		// RFC 8439 §A.3 Test Vector #1
		description: 'RFC 8439 §A.3 vec 1: zero key, 64 zero bytes → zero tag',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		msg:
      '0000000000000000000000000000000000000000000000000000000000000000' +
      '0000000000000000000000000000000000000000000000000000000000000000',
		tag: '00000000000000000000000000000000',
	},
	{
		// RFC 8439 §A.3 Test Vector #4 — Jabberwocky (127 bytes)
		// Key: 1c9240a5 eb55d38a f3338886 04f6b5f0 473917c1 402b8009 9dca5cbc 207075c0
		description: 'RFC 8439 §A.3 vec 4: Jabberwocky text (127 bytes)',
		key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
		// Message: ASCII "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe."
		msgText:
      '\'Twas brillig, and the slithy toves\n' +
      'Did gyre and gimble in the wabe:\n' +
      'All mimsy were the borogoves,\n' +
      'And the mome raths outgrabe.',
		tag: '4541669a7eaaee61e708dc7cbcc5eb62',
	},
];

// ============================================================
// RFC 8439 §A.4 — Poly1305 key generation
// ============================================================

export interface Poly1305KeyGenVector {
  description: string;
  key:         string; // 32 bytes (ChaCha20 key)
  nonce:       string; // 12 bytes (ChaCha20 nonce)
  poly1305Key: string; // 32 bytes (first 32 bytes of block at counter=0)
}

/** RFC 8439 Appendix A.4 test vectors for Poly1305 key generation. */
export const poly1305KeyGenVectors: Poly1305KeyGenVector[] = [
	{
		// RFC 8439 §A.4 Test Vector #1
		// poly1305Key = chacha20Block(zero_key, 0, zero_nonce)[0..31]
		//             = first 32 bytes of §A.2.1 keystream
		description: 'RFC 8439 §A.4 vec 1: zero key + zero nonce',
		key: '0000000000000000000000000000000000000000000000000000000000000000',
		nonce: '000000000000000000000000',
		poly1305Key:
      '76b8e0ada0f13d90405d6ae55386bd28' +
      'bdd219b8a08ded1aa836efcc8b770dc7',
	},
];

// ============================================================
// HChaCha20 — XChaCha20 IETF draft §2.2.1
// ============================================================

export interface HChaCha20Vector {
  description: string;
  key:     string; // 32 bytes
  nonce16: string; // 16 bytes — fills all 4 state words 12-15 (no counter)
  subkey:  string; // 32 bytes = LE(words 0-3) || LE(words 12-15) after rounds
}

/** XChaCha20 draft §2.2.1 test vector for HChaCha20. */
export const hchacha20Vectors: HChaCha20Vector[] = [
	{
		// XChaCha20 IETF draft (draft-irtf-cfrg-xchacha-03) §2.2.1
		// State after 20 rounds (no initial-state addition):
		//   words 0-3:   423b4182 fe7bb227 50420ed3 737d878a  → 82413b42 27b27bfe d30e4250 8a877d73
		//   words 12-15: d5e4f9a0 53a8748a 13c42ec1 dcecd326  → a0f9e4d5 8a74a853 c12ec413 26d3ecdc
		description: 'XChaCha20 draft §2.2.1: sequential key, non-zero nonce16',
		key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		nonce16: '000000090000004a0000000031415927',
		subkey:
      '82413b4227b27bfed30e42508a877d73' +
      'a0f9e4d58a74a853c12ec41326d3ecdc',
	},
];

// ============================================================
// AEAD_CHACHA20_POLY1305 — RFC 8439 §2.8.2
// ============================================================

export interface AeadVector {
  description: string;
  key:     string;  // 32 bytes
  nonce:   string;  // 12 bytes (ChaCha20Poly1305) or 24 bytes (XChaCha20Poly1305)
  aad:     string;  // hex
  pt?:     string;  // plaintext hex (optional if ptText is set)
  ptText?: string;  // plaintext as UTF-8 text (encoded via TextEncoder in tests)
  ct:      string;  // ciphertext hex (same length as plaintext)
  tag:     string;  // 16 bytes
}

/** RFC 8439 §2.8.2 AEAD test vectors for AEAD_CHACHA20_POLY1305. */
export const chacha20Poly1305Vectors: AeadVector[] = [
	{
		// RFC 8439 §2.8.2 — "Sunscreen" example
		description: 'RFC 8439 §2.8.2: sunscreen AEAD example (114-byte plaintext)',
		key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
		nonce: '070000004041424344454647',
		aad: '50515253c0c1c2c3c4c5c6c7',
		// Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
		ptText:
      'Ladies and Gentlemen of the class of \'99: If I could offer you' +
      ' only one tip for the future, sunscreen would be it.',
		// Ciphertext from RFC 8439 §2.8.2 (114 bytes)
		ct:
      'd31a8d34648e60db7b86afbc53ef7ec2' +
      'a4aded51296e08fea9e2b5a736ee62d6' +
      '3dbea45e8ca9671282fafb69da92728b' +
      '1a71de0a9e060b2905d6a5b67ecd3b36' +
      '92ddbd7f2d778b8c9803aee328091b58' +
      'fab324e4fad675945585808b4831d7bc' +
      '3ff4def08e4b7a9de576d26586cec64b' +
      '6116',
		tag: '1ae10b594f09e26a7e902ecbd0600691',
	},
];

/** XChaCha20-Poly1305 AEAD test vector from XChaCha20 draft Appendix A.1. */
export const xchacha20Poly1305Vectors: AeadVector[] = [
	{
		// XChaCha20 draft Appendix A.1 — same "sunscreen" text, 24-byte nonce
		description: 'XChaCha20 draft A.1: sunscreen AEAD example (24-byte nonce)',
		key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
		nonce: '404142434445464748494a4b4c4d4e4f5051525354555657', // 24 bytes
		aad: '50515253c0c1c2c3c4c5c6c7',
		ptText:
      'Ladies and Gentlemen of the class of \'99: If I could offer you' +
      ' only one tip for the future, sunscreen would be it.',
		// Ciphertext from draft Appendix A.1 (114 bytes)
		ct:
      'bd6d179d3e83d43b9576579493c0e939' +
      '572a1700252bfaccbed2902c21396cbb' +
      '731c7f1b0b4aa6440bf3a82f4eda7e39' +
      'ae64c6708c54c216cb96b72e1213b452' +
      '2f8c9ba40db5d945b11b69b982c1bb9e' +
      '3f3fac2bc369488f76b2383565d3fff9' +
      '21f9664c97637da9768812f615c68b13' +
      'b52e',
		tag: 'c0875924c1c7987947deafd8780acf49',
	},
];
