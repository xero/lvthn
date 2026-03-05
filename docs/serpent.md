# serpent.ts

Serpent-256 block cipher — 128-bit block, 128/192/256-bit key, 32-round bitslice implementation.

---

## Overview

Serpent is a symmetric block cipher designed by Ross Anderson, Eli Biham, and Lars Knudsen
as a candidate for the Advanced Encryption Standard (AES). It was the finalist with the
highest security margin: 32 rounds versus AES's 10/12/14, chosen deliberately to provide
a large conservative margin against cryptanalytic attacks. No practical attack on the full
32-round Serpent exists as of 2026.

This implementation uses **AES-submission byte ordering**, the format submitted by Ross
Anderson to the AES competition in 1998. This differs from the NESSIE test vector format
(which uses standard big-endian word order). Inputs to `encrypt()` and `decrypt()` do not
require any byte-order preprocessing when compared against the original AES submission
vectors in `test/vectors/` — they work directly. If you are interoperating with NESSIE
vectors, apply a full byte-reversal of key and plaintext before calling and reverse the
output; see `test/helpers/nessie.ts` for the helper.

Five classes are exported, covering all common use cases:

| Class | Mode | Padding | Use when |
|-------|------|---------|----------|
| `Serpent` | ECB | None | Single 16-byte block operations; building custom modes |
| `Serpent_CBC` | CBC | None | Encrypting aligned data with your own padding |
| `Serpent_CTR` | CTR | None | Streaming / arbitrary-length data |
| `Serpent_CBC_PKCS7` | CBC | PKCS7 | Most common case — arbitrary-length plaintexts with CBC |
| `Serpent_CTR_PKCS7` | CTR | PKCS7 | CTR with automatic length padding |

**Recommendation:** Use `Serpent_CBC_PKCS7` or `Serpent_CTR_PKCS7` for all new code.
Use a 256-bit key. Never use bare `Serpent` (raw ECB) for more than one block.

---

## Security Notes

**Key size:** 128, 192, or 256-bit keys are accepted. Use 256-bit (32 bytes) for all new
applications. Shorter keys reduce the security margin unnecessarily.

**Bitslice implementation:** S-boxes are implemented as Boolean gate circuits (`&`, `|`,
`^`, `~` on 32-bit integers) with no table lookups and no data-dependent branches. This
eliminates cache-timing side-channels that affect table-based implementations. JavaScript
engines do not provide formal constant-time guarantees; the bitslice design eliminates the
most practical attack vector but a formally proven constant-time guarantee requires
WebAssembly or native code.

**ECB mode warning:** Raw `Serpent.encrypt()` and `Serpent.decrypt()` operate in ECB
mode — identical plaintext blocks produce identical ciphertext blocks. Do not use ECB
for more than a single block. Use a mode wrapper (`Serpent_CBC` / `Serpent_CTR`) for
all multi-block encryption.

**CBC IV requirements:** The IV passed to `Serpent_CBC` and `Serpent_CBC_PKCS7` must be
random and unpredictable. Reusing an IV under the same key leaks information about
whether the first block of two plaintexts is identical. Generate a fresh IV with `Random`
for every encryption.

**CTR nonce requirements:** The nonce (IV) passed to `Serpent_CTR` and `Serpent_CTR_PKCS7`
must be unique per encryption under the same key. Nonce reuse in CTR mode is catastrophic:
XOR of two ciphertexts directly reveals the XOR of the two plaintexts. Never reuse a
CTR nonce.

**Test coverage:** This implementation has been verified against:
- All AES candidate submission vectors from `floppy4/` (ecb_vt, ecb_vk, ecb_tbl, ecb_iv)
- Monte Carlo ECB and CBC tests (1200 × 10,000 iterations each)
- 1284 NESSIE Serpent-256 vectors (encrypt + decrypt)
- 1028 NESSIE Serpent-128 vectors (encrypt + decrypt)
- CTR vectors independently generated from the Ross Anderson reference C implementation

---

## API Reference

### `RoundHook`

```typescript
type RoundHook = (round: number, state: number[], ec: number) => void;
```

Optional debug callback set on `Serpent.roundHook`. Called after each of the 32
encryption or decryption rounds with the current internal state. Intended for testing
and verification only — do not use in production code.

**Parameters:**
- `round` — round index 0–31
- `state` — snapshot of the 5-element working register array `r[0..4]`
- `ec` — the EC/DC constant for this round; use `ec%5`, `ec%7`, `ec%11`, `ec%13` to
  identify which `r[]` slots hold X0, X1, X2, X3 respectively

---

### `class Serpent`

Raw ECB block cipher. Operates on exactly 16 bytes at a time.

#### `encrypt(key: Uint8Array, pt: Uint8Array): Uint8Array`

Encrypts a single 128-bit block.

**Parameters:**
- `key` — 16, 24, or 32 bytes (128, 192, or 256-bit key)
- `pt` — exactly 16 bytes of plaintext

**Returns:** 16-byte ciphertext `Uint8Array`

**Example:**
```typescript
import { Serpent, Convert } from 'leviathan';

const s   = new Serpent();
const key = Convert.hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const pt  = Convert.hex2bin('00112233445566778899aabbccddeeff');
const ct  = s.encrypt(key, pt);
console.log(Convert.bin2hex(ct));
```

---

#### `decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array`

Decrypts a single 128-bit block.

**Parameters:**
- `key` — 16, 24, or 32 bytes (must match the key used for encryption)
- `ct` — exactly 16 bytes of ciphertext

**Returns:** 16-byte plaintext `Uint8Array`

---

#### `getSubkeys(key: Uint8Array): Uint32Array`

Returns a copy of the 132-word derived subkey schedule for debugging and testing.
`this.key[4*i .. 4*i+3]` = `[X0, X1, X2, X3]` for subkey `i` (i = 0..32).

**Parameters:**
- `key` — 16, 24, or 32 bytes

**Returns:** `Uint32Array(132)` — 33 subkeys × 4 words each

---

#### `selftest(): boolean`

Verifies the implementation against a known-answer test from the AES submission.

**Returns:** `true` if the implementation is correct

---

### `class Serpent_CBC`

Serpent in CBC mode without padding. Plaintext length must be a multiple of 16 bytes.

#### `encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array`

**Parameters:**
- `key` — 16, 24, or 32 bytes
- `pt` — plaintext (length must be a multiple of 16 bytes)
- `iv` — 16-byte random IV (must be unique and unpredictable per encryption)

**Returns:** ciphertext `Uint8Array` (same length as `pt`)

#### `decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array`

**Parameters:**
- `key` — 16, 24, or 32 bytes
- `ct` — ciphertext (length must be a multiple of 16 bytes)
- `iv` — the same 16-byte IV used during encryption

**Returns:** plaintext `Uint8Array`

---

### `class Serpent_CTR`

Serpent in CTR mode without padding. Accepts arbitrary-length plaintexts.

#### `encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array`

**Parameters:**
- `key` — 16, 24, or 32 bytes
- `pt` — plaintext (any length)
- `iv` — 16-byte nonce (must be unique per encryption under the same key)

**Returns:** ciphertext `Uint8Array` (same length as `pt`)

#### `decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array`

CTR decryption is identical to encryption (XOR stream). Parameters and return type
mirror `encrypt()`.

---

### `class Serpent_CBC_PKCS7`

Serpent in CBC mode with PKCS7 padding. Accepts arbitrary-length plaintexts.

#### `encrypt(key: Uint8Array, pt: Uint8Array, iv: Uint8Array): Uint8Array`

Pads `pt` to a 16-byte boundary using PKCS7, then encrypts with CBC.

**Parameters:** same as `Serpent_CBC.encrypt()`

**Returns:** padded ciphertext (length = next multiple of 16 ≥ `pt.length + 1`)

#### `decrypt(key: Uint8Array, ct: Uint8Array, iv: Uint8Array): Uint8Array`

Decrypts with CBC then strips PKCS7 padding.

**Parameters:** same as `Serpent_CBC.decrypt()`

**Returns:** original plaintext (padding removed)

---

### `class Serpent_CTR_PKCS7`

Serpent in CTR mode with PKCS7 padding. Accepts arbitrary-length plaintexts.
API mirrors `Serpent_CBC_PKCS7`.

---

## Usage Examples

### Recommended: CBC with PKCS7 and a random IV

```typescript
import { Serpent_CBC_PKCS7, Random, Convert } from 'leviathan';

const rng    = new Random();
const cipher = new Serpent_CBC_PKCS7();

const key  = rng.get(32)!;  // 256-bit key
const iv   = rng.get(16)!;  // fresh random IV per message

const message    = Convert.str2bin('Sensitive payload that may not be block-aligned.');
const ciphertext = cipher.encrypt(key, message, iv);

// Store/transmit iv alongside ciphertext — it is not secret
const plaintext = cipher.decrypt(key, ciphertext, iv);
console.log(Convert.bin2str(plaintext));
```

### CTR mode for streaming data

```typescript
import { Serpent_CTR, Random, Convert } from 'leviathan';

const rng    = new Random();
const cipher = new Serpent_CTR();

const key   = rng.get(32)!;
const nonce = rng.get(16)!;  // unique per message — NEVER reuse with the same key

const ct = cipher.encrypt(key, Convert.str2bin('stream data'), nonce);
const pt = cipher.decrypt(key, ct, nonce);  // CTR decrypt = encrypt
```

### Raw ECB (single block only)

```typescript
import { Serpent, Convert } from 'leviathan';

// Only safe for single-block operations (e.g. constructing a custom mode)
const s   = new Serpent();
const key = Convert.hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const pt  = new Uint8Array(16);  // exactly one block
const ct  = s.encrypt(key, pt);
const dec = s.decrypt(key, ct);
```

---

## Error Conditions

- **Wrong key length:** No exception is thrown. The init routine reads `key.length` and
  pads the key to 256 bits internally. Passing a key shorter than 16 bytes will produce
  an incorrect (non-standard) key schedule. Always pass 16, 24, or 32 bytes.
- **Wrong block length (raw Serpent):** No exception. `encrypt()` creates an output buffer
  the same length as `pt` but only processes the first 16 bytes correctly if `pt.length ≠ 16`.
- **CBC with unaligned plaintext:** No exception from `Serpent_CBC`; use `Serpent_CBC_PKCS7`
  to handle arbitrary lengths automatically.
- **Null/undefined inputs:** Will throw a runtime `TypeError`. Validate inputs before calling.

---

## See Also

- [blockmode.ts](./blockmode.md) — CBC and CTR mode implementations used by the wrapper classes
- [padding.ts](./padding.md) — PKCS7 padding used by the `_PKCS7` variants
- [random.ts](./random.md) — CSPRNG for generating keys and IVs
- [index.ts](./index.md) — library overview and quick start
