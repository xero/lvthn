# padding.ts

PKCS#7 padding — pad and strip arbitrary-length byte arrays to block boundaries.

---

## Overview

`padding.ts` exports a single class, `PKCS7`, implementing PKCS#7 padding (RFC 5652 §6.3).

PKCS#7 padding ensures that a byte array is an exact multiple of a given block size. It
appends `n` bytes each with the value `n`, where `n` is the number of bytes needed to
reach the next block boundary. The minimum pad is 1 byte (never zero); the maximum pad
is `blocksize` bytes (a full padding block is appended when the input is already aligned).

**In practice, you will rarely use `PKCS7` directly.** The `Serpent_CBC_PKCS7` and
`Serpent_CTR_PKCS7` classes in `serpent.ts` compose padding with the cipher and are the
recommended API for arbitrary-length plaintext encryption.

---

## Security Notes

**`strip()` does not validate padding.** The `strip()` method trusts the last byte as the
pad length without checking that all pad bytes match. If the input was not correctly
padded (e.g. a decryption of a tampered ciphertext), `strip()` will silently return a
wrong-length slice rather than throwing an error.

This is a **padding oracle risk** if used naively. In a padding oracle attack, an
attacker queries whether a decrypted block has valid padding to learn plaintext bytes
one at a time. The correct mitigation is to verify the MAC **before** decrypting and
stripping padding — never strip padding on unauthenticated ciphertext.

**Always authenticate before decrypting.** When using `Serpent_CBC_PKCS7`, combine it
with `HMAC_SHA256` in an Encrypt-then-MAC scheme: compute an HMAC over the IV and
ciphertext, verify it with `constantTimeEqual` before calling `decrypt()`.

**PKCS7 always adds at least 1 byte of padding.** Even when `bin.length` is already a
multiple of `blocksize`, a full padding block (`blocksize` bytes, each equal to
`blocksize`) is appended. This is correct per the spec and ensures that the pad can
always be unambiguously stripped.

---

## API Reference

### `class PKCS7`

#### `pad(bin: Uint8Array, blocksize: number): Uint8Array`

Returns a new array with PKCS#7 padding appended.

**Parameters:**
- `bin` — input byte array (any length)
- `blocksize` — target block size in bytes (e.g. 16 for Serpent/AES)

**Returns:** new `Uint8Array` of length `bin.length + n`, where `n` satisfies:
- `1 ≤ n ≤ blocksize`
- `(bin.length + n) % blocksize === 0`

Each of the `n` appended bytes has the value `n`.

**Example:**
```typescript
import { PKCS7 } from 'leviathan';

const pkcs7  = new PKCS7();
const input  = new Uint8Array([0x01, 0x02, 0x03]);  // 3 bytes
const padded = pkcs7.pad(input, 16);

// padded.length === 16
// padded[3..15] === 0x0d (13), the pad length
```

---

#### `strip(bin: Uint8Array): Uint8Array`

Returns a view of `bin` with the PKCS#7 padding removed.

**Parameters:**
- `bin` — padded byte array (length must be a multiple of the block size)

**Returns:** `Uint8Array` subarray (not a copy) of length `bin.length - bin[bin.length - 1]`

**Note:** Returns a subarray (a view into the original buffer), not a copy. Modifying
the returned slice will modify the original array.

**Example:**
```typescript
import { PKCS7 } from 'leviathan';

const pkcs7    = new PKCS7();
const padded   = new Uint8Array([0x01, 0x02, 0x03, 0x0d, 0x0d, /* ... */ 0x0d]);  // 16 bytes
const stripped = pkcs7.strip(padded);

// stripped.length === 3
// stripped === [0x01, 0x02, 0x03]
```

---

## Usage Examples

### Manual pad and strip round-trip

```typescript
import { PKCS7, Convert } from 'leviathan';

const pkcs7   = new PKCS7();
const message = Convert.str2bin('Hello!');  // 6 bytes

const padded   = pkcs7.pad(message, 16);   // 16 bytes, 10 pad bytes each = 0x0a
const stripped = pkcs7.strip(padded);

console.log(Convert.bin2str(stripped));    // "Hello!"
```

---

### Via the Serpent_CBC_PKCS7 wrapper (recommended)

```typescript
import { Serpent_CBC_PKCS7, Random, Convert } from 'leviathan';

const rng    = new Random();
const cipher = new Serpent_CBC_PKCS7();

const key  = rng.get(32)!;
const iv   = rng.get(16)!;
const msg  = Convert.str2bin('arbitrary length message');

// Padding is applied automatically
const ct = cipher.encrypt(key, msg, iv);
const pt = cipher.decrypt(key, ct, iv);  // padding is stripped automatically
```

---

## Error Conditions

- **`strip()` on invalid padding:** No exception. If the last byte value is larger than
  `bin.length`, `subarray(0, negative)` returns an empty array. If the padding bytes are
  inconsistent (e.g. tampered ciphertext), the wrong number of bytes will be stripped
  silently. Always authenticate before decrypting to prevent this scenario.
- **`pad()` with `blocksize = 0`:** Will produce `n = 0` (division by zero: `bin.length % 0`
  is `NaN`; the ternary then takes the false branch with `len = blocksize = 0`), returning
  a zero-length extension — effectively a no-op. Do not call with `blocksize = 0`.
- **Null/undefined inputs:** Will throw a runtime `TypeError`.

---

## See Also

- [serpent.ts](./serpent.md) — `Serpent_CBC_PKCS7` and `Serpent_CTR_PKCS7` wrappers
- [blockmode.ts](./blockmode.md) — CBC mode (requires block-aligned input without PKCS7)
- [Wiki Home](./README.md) — library overview
