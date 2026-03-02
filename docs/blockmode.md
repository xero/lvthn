# blockmode.ts

Block cipher mode-of-operation wrappers (CBC, CTR) and AEAD schemes (ChaCha20-Poly1305, XChaCha20-Poly1305).

---

## Overview

Block ciphers like Serpent operate on fixed-size blocks (16 bytes). To encrypt arbitrary
data, a mode of operation is required to chain block-cipher calls in a way that provides
semantic security. This module provides two modes: CBC and CTR.

**ECB mode has been deliberately removed.** ECB (Electronic Codebook) produces identical
ciphertext blocks for identical plaintext blocks, making patterns in the plaintext visible
in the ciphertext — the canonical illustration is the "ECB penguin" where an image
encrypted in ECB mode retains its visible structure. ECB is unsafe for any multi-block
message.

In practice you will rarely use `CBC` or `CTR` directly. The `Serpent_CBC`, `Serpent_CTR`,
`Serpent_CBC_PKCS7`, and `Serpent_CTR_PKCS7` classes in `serpent.ts` compose these modes
with a concrete cipher and are the recommended API.

**CBC vs CTR tradeoffs:**

| | CBC | CTR |
|-|-----|-----|
| Requires block-aligned input | Yes | No |
| Parallelisable decrypt | Yes | Yes |
| Parallelisable encrypt | No | Yes |
| Nonce reuse consequence | Leaks first-block equality | Catastrophic (XOR key stream) |
| Requires padding | Yes (use PKCS7 variant) | No |
| Ciphertext length | ≥ plaintext length | Equal to plaintext length |

---

## Security Notes

**CBC IV requirements:** The IV for CBC must be randomly generated and unpredictable for
each new encryption under the same key. A predictable IV (e.g. sequential counter) enables
chosen-plaintext attacks (the BEAST attack on TLS 1.0 exploited predictable CBC IVs).
The IV is not secret and is typically prepended to the ciphertext.

**CTR nonce requirements:** The nonce for CTR must be unique for every encryption under
the same key. Nonce reuse in CTR is catastrophic: two ciphertexts encrypted with the
same key and nonce have the property that `CT1 XOR CT2 = PT1 XOR PT2`, which directly
exposes the XOR of the two plaintexts. With sufficient ciphertext pairs, the individual
plaintexts can often be recovered completely. Never reuse a CTR nonce.

**Counter increment:** The CTR counter is incremented little-endian (byte 0 first, carry
propagates to byte 1, etc.). This matches the leviathan CTR vector test suite, which was
independently verified against the Ross Anderson reference C implementation.

**Input length:** Neither CBC nor CTR validates that input length is a multiple of the
block size. CBC will produce incorrect output silently if given unaligned input. Use the
`_PKCS7` variants in `serpent.ts` for automatic padding.

**ECB removal rationale:** ECB was present in the original library alongside AES. When
AES was removed from leviathan (Phase 2 of the audit), ECB was also removed because no
safe use case for ECB on more than one block exists in a general-purpose library.

---

## API Reference

### `class CBC`

Cipher Block Chaining mode. Requires input length to be a multiple of `blockcipher.blockSize`.

#### `constructor(blockcipher: Blockcipher)`

**Parameters:**
- `blockcipher` — any object implementing the `Blockcipher` interface (`blockSize`, `encrypt`, `decrypt`)

**Example:**
```typescript
import { CBC } from 'leviathan';
import { Serpent } from 'leviathan';

const cbc = new CBC(new Serpent());
```

---

#### `encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array`

Encrypts `pt` using CBC mode.

**Parameters:**
- `key` — key bytes for the underlying block cipher
- `pt` — plaintext; length must be a multiple of `blockcipher.blockSize`
- `iv` — random unpredictable IV; same length as `blockcipher.blockSize`

**Returns:** ciphertext `Uint8Array`, same length as `pt`

---

#### `decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array`

Decrypts `ct` using CBC mode.

**Parameters:**
- `key` — key bytes (must match encryption key)
- `ct` — ciphertext; length must be a multiple of `blockcipher.blockSize`
- `iv` — the same IV used during encryption

**Returns:** plaintext `Uint8Array`, same length as `ct`

---

### `class CTR`

Counter mode. Accepts arbitrary-length input; decryption is identical to encryption.

#### `constructor(blockcipher: Blockcipher)`

**Parameters:**
- `blockcipher` — any `Blockcipher` implementation

---

#### `encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array`

Encrypts `pt` using CTR mode. The counter starts at `iv` and is incremented
little-endian after each block.

**Parameters:**
- `key` — key bytes for the underlying block cipher
- `pt` — plaintext (any length; the output length equals the input length)
- `iv` — unique nonce per encryption; same length as `blockcipher.blockSize`

**Returns:** ciphertext `Uint8Array`, same length as `pt`

---

#### `decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array`

CTR decryption is identical to encryption — the keystream is XOR'd again to recover
the plaintext. Parameters and return type mirror `encrypt()`.

---

## Usage Examples

### Direct CBC usage (requires pre-padded input)

```typescript
import { CBC, Serpent, Random, Convert } from 'leviathan';

const rng  = new Random();
const cbc  = new CBC(new Serpent());
const key  = rng.get(32)!;
const iv   = rng.get(16)!;

// Input must be block-aligned (multiple of 16 bytes)
const pt = new Uint8Array(32);  // two blocks of zeros
const ct = cbc.encrypt(key, pt, iv);
const recovered = cbc.decrypt(key, ct, iv);
```

### Direct CTR usage

```typescript
import { CTR, Serpent, Random, Convert } from 'leviathan';

const rng   = new Random();
const ctr   = new CTR(new Serpent());
const key   = rng.get(32)!;
const nonce = rng.get(16)!;

const message = Convert.str2bin('arbitrary length message — no padding needed');
const ct      = ctr.encrypt(key, message, nonce);
const pt      = ctr.decrypt(key, ct, nonce);
console.log(Convert.bin2str(pt));
```

---

## Error Conditions

- **Unaligned plaintext in CBC:** No exception is thrown. The loop processes `Math.floor(pt.length / bs)` blocks. Bytes beyond the last full block are silently ignored in the output. Use the `Serpent_CBC_PKCS7` wrapper to handle arbitrary lengths.
- **IV length mismatch:** No exception. If `iv.length < blockSize`, the `|| 0` fallback fills missing bytes with zero — this is not an error but reduces the IV entropy. Always pass a full-length IV.
- **Null/undefined inputs:** Will throw a runtime `TypeError`.

---

---

## AEAD: ChaCha20-Poly1305 and XChaCha20-Poly1305

In addition to `CBC` and `CTR`, `blockmode.ts` exports two AEAD (Authenticated
Encryption with Associated Data) classes:

| Class | Nonce size | RFC / spec | Recommended |
|-------|-----------|-----------|-------------|
| `XChaCha20Poly1305` | 24 bytes (192-bit) | XChaCha20 IETF draft | Yes — random nonces safe |
| `ChaCha20Poly1305` | 12 bytes (96-bit) | RFC 8439 | Only with counter nonces |

These classes combine ChaCha20 stream encryption with Poly1305 authentication in a single
operation. The tag covers both the ciphertext and optional additional authenticated data
(AAD). `decrypt()` always verifies the tag before returning any plaintext.

See [chacha20poly1305.md](./chacha20poly1305.md) for full documentation, security notes,
usage examples, and what to transmit.

```typescript
import { XChaCha20Poly1305, Random } from 'leviathan';

const rng   = new Random();
const aead  = new XChaCha20Poly1305();
const key   = rng.get(32)!;
const nonce = rng.get(24)!;

const { ciphertext, tag } = aead.encrypt(key, nonce, plaintext);
const recovered           = aead.decrypt(key, nonce, ciphertext, tag);
```

---

## See Also

- [chacha20poly1305.ts](./chacha20poly1305.md) — full AEAD documentation
- [serpent.ts](./serpent.md) — `Serpent_CBC`, `Serpent_CTR`, `Serpent_CBC_PKCS7`, `Serpent_CTR_PKCS7` convenience wrappers
- [padding.ts](./padding.md) — PKCS7 padding for CBC with arbitrary-length input
- [index.ts](./index.md) — library overview
