# chacha20.ts

ChaCha20 stream cipher — 256-bit key, 64-bit nonce, arbitrary-length plaintext.

---

## Overview

`chacha20.ts` exports a single class, `ChaCha20`, implementing the ChaCha20 stream
cipher by D. J. Bernstein. The implementation is derived from the reference `chacha.c`
(cr.yp.to/chacha.html).

ChaCha20 is a stream cipher operating in 512-bit (64-byte) blocks. It initialises a
16-word state from the key, nonce, counter, and the constant `"expand 32-byte k"`, then
applies 20 rounds of the quarter-round mix function (10 double-rounds: 4 column rounds
followed by 4 diagonal rounds) to produce a keystream block. The plaintext is XOR'd with
the keystream.

**Decryption is identical to encryption.** XOR-ing the ciphertext with the same keystream
recovers the plaintext. `decrypt()` calls the same `stream()` function as `encrypt()`.

---

## Security Notes

**Nonce must be unique per encryption under the same key.** ChaCha20 is a stream cipher:
two messages encrypted with the same key and nonce produce keystreams that XOR to cancel
out, directly exposing `PT1 XOR PT2`. As with CTR mode, nonce reuse is catastrophic.
Generate a fresh 8-byte nonce with `Random.get(8)` for every message.

**Nonce size is 8 bytes (64 bits), not 12 bytes.** This implementation follows the
original Bernstein specification with an 8-byte nonce and a 64-bit counter split across
`input[12]` (low 32 bits) and `input[13]` (high 32 bits). RFC 7539 / IETF ChaCha20
uses a 12-byte nonce and a 32-bit counter. These are **not interoperable**. If your
counterparty uses RFC 7539 ChaCha20 (e.g. TLS 1.3), use a separate implementation.

**Counter overflow:** The counter is a 64-bit value (two `Uint32Array` words). The
maximum message length is 2^64 × 64 bytes ≈ 10^21 bytes, which is effectively unlimited.

**No authentication.** ChaCha20 is unauthenticated. An attacker who can flip ciphertext
bits will flip corresponding plaintext bits silently. For authenticated encryption (AEAD),
use `XChaCha20Poly1305` or `ChaCha20Poly1305` from `blockmode.ts` — they combine
ChaCha20 with Poly1305 per RFC 8439. Alternatively, pair this class with HMAC using
Encrypt-then-MAC.

**`selftest()` always returns `true`** without performing any verification. It is a
stub. Use the Vitest test vectors in `test/spec/12_chacha20.test.ts` to validate
correctness.

---

## API Reference

### `class ChaCha20`

Implements the `Streamcipher` interface.

Properties:
- `keySize: number` — always 32 (256-bit key)
- `nonceSize: number` — always 8 (64-bit nonce)

#### `constructor()`

No parameters.

**Example:**
```typescript
import { ChaCha20 } from 'leviathan';
const chacha = new ChaCha20();
```

---

#### `encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array, cnt?: number): Uint8Array`

Encrypts `pt` by XOR-ing it with the ChaCha20 keystream.

**Parameters:**
- `key` — 32-byte (256-bit) secret key
- `pt` — plaintext, any length
- `iv` — 8-byte (64-bit) nonce; must be unique per encryption under the same key
- `cnt` — optional initial counter value (default: 0); useful for random access into
  the keystream at a specific 64-byte block offset

**Returns:** `Uint8Array` of the same length as `pt`

**Example:**
```typescript
import { ChaCha20, Random, Convert } from 'leviathan';

const rng    = new Random();
const chacha = new ChaCha20();

const key   = rng.get(32)!;  // 256-bit key
const nonce = rng.get(8)!;   // 64-bit nonce — NEVER reuse with the same key
const msg   = Convert.str2bin('plaintext message');
const ct    = chacha.encrypt(key, msg, nonce);
```

---

#### `decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array, cnt?: number): Uint8Array`

Decrypts `ct`. Identical to `encrypt()` — XOR is its own inverse.

**Parameters:** same as `encrypt()`

**Returns:** `Uint8Array` of the same length as `ct`

---

#### `selftest(): boolean`

Always returns `true` (stub). Use the test suite for correctness validation.

---

## Usage Examples

### Encrypt and decrypt

```typescript
import { ChaCha20, Random, Convert } from 'leviathan';

const rng    = new Random();
const chacha = new ChaCha20();

const key   = rng.get(32)!;
const nonce = rng.get(8)!;  // unique per message

const msg = Convert.str2bin('Hello, ChaCha20!');
const ct  = chacha.encrypt(key, msg, nonce);
const pt  = chacha.decrypt(key, ct, nonce);
console.log(Convert.bin2str(pt));  // "Hello, ChaCha20!"
```

---

### Random-access keystream (counter offset)

```typescript
import { ChaCha20, Convert } from 'leviathan';

const chacha = new ChaCha20();
const key    = /* 32-byte key */;
const nonce  = /* 8-byte nonce */;

// Decrypt block 100 (bytes 6400–6463) directly
// by setting the counter to 100:
const blockSlice = ciphertext.subarray(6400, 6464);
const pt100      = chacha.decrypt(key, blockSlice, nonce, 100);
```

---

## Error Conditions

- **Key not 32 bytes:** No exception. The `init()` function reads `key[0..31]` regardless
  of `key.length`. A shorter key will read past its end (`undefined`, coercing to 0 in
  typed-array operations) and produce a non-standard, likely weak state. Always pass
  exactly 32 bytes.
- **Nonce not 8 bytes:** No exception. Only `nonce[0..7]` are read. Passing fewer bytes
  yields a partially-zero nonce, which may collide with other nonces. Always pass exactly
  8 bytes.
- **Null/undefined inputs:** Will throw a runtime `TypeError`.

---

## See Also

- [chacha20poly1305.ts](./chacha20poly1305.md) — ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD (recommended over bare ChaCha20)
- [random.ts](./random.md) — CSPRNG for generating keys and nonces
- [hmac.ts](./hmac.md) — HMAC for Encrypt-then-MAC if AEAD is unavailable
- [serpent.ts](./serpent.md) — Serpent block cipher with CTR mode as an alternative stream cipher
- [index.ts](./index.md) — library overview
