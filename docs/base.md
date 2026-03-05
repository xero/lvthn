# base.ts

Core interfaces, format converters (`Convert`), utility functions (`Util`), and `constantTimeEqual`.

---

## Overview

`base.ts` is the foundation of the leviathan library. It exports:

- **TypeScript interfaces** (`Blockcipher`, `Streamcipher`, `Hash`, `KeyedHash`, `Signature`,
  `PublicKey`) that every crypto primitive implements. These are used internally for type
  safety and can be used in application code for dependency injection or duck-typing.

- **`Convert` namespace** — format conversion functions covering UTF-8 strings, hex,
  base64/base64url, little-endian integers, and typed arrays. These are the primary
  mechanism for feeding data into and reading data out of the library.

- **`constantTimeEqual`** — a standalone constant-time byte-array comparison function
  added in Phase 7 of the security audit. This is the canonical way to compare secret
  values (MACs, tags, keys) without leaking timing information.

- **`Util` namespace** — byte-array utilities: `compare` (delegates to `constantTimeEqual`),
  `clear`, `xor`, `concat`, `litteendian`.

- **`version`** — library version string.

---

## Security Notes

`constantTimeEqual` is used internally wherever the comparison result could enable an
attack if timing information leaked: Ed25519 signature verification and Curve25519 point
comparison in `x25519.ts`. `Util.compare` delegates to `constantTimeEqual` so both
APIs provide the same guarantee.

**The length check in `constantTimeEqual` is not constant-time.** This is intentional and
safe: in all protocols where this is used, the expected tag or signature length is public
information. An attacker who already knows the expected length gains nothing from
measuring whether the length check passed quickly.

**Do not implement your own comparison loop** for security-sensitive values. Use
`constantTimeEqual` or `Util.compare`.

The `Convert` namespace, `Util.clear`, `Util.xor`, `Util.concat`, and `Util.litteendian`
contain no security-sensitive operations. They are format converters and byte-manipulation
utilities with no secret data exposure concerns of their own — the security of any
operation using them depends on how the caller handles the input and output.

---

## API Reference

### `version: string`

Library version string (e.g. `'1.1.4'`).

---

### `constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean`

Constant-time byte-array equality test using XOR-accumulate.

Compares two `Uint8Array`s without short-circuiting on the first differing byte.
Ordinary equality checks reveal where two values diverge via execution time,
enabling byte-at-a-time MAC forgery attacks (Lucky Thirteen, Vaudenay padding oracle).

**Parameters:**
- `a` — first byte array
- `b` — second byte array

**Returns:** `true` if and only if `a` and `b` have equal length and identical content

**Example:**
```typescript
import { constantTimeEqual, Convert } from 'leviathan';

const received = Convert.hex2bin('aabbccdd...');
const expected = Convert.hex2bin('aabbccdd...');
if (!constantTimeEqual(received, expected)) {
  throw new Error('MAC verification failed');
}
```

---

### `namespace Convert`

#### `str2bin(str: string): Uint8Array`

Converts a UTF-8 string to a byte array.

**Parameters:**
- `str` — any JavaScript string (UTF-8 encoded; `\r\n` is normalised to `\n`)

**Returns:** `Uint8Array` of UTF-8 encoded bytes

---

#### `bin2str(bin: Uint8Array): string`

Converts a UTF-8 byte array back to a JavaScript string.

**Parameters:**
- `bin` — UTF-8 bytes

**Returns:** decoded string

---

#### `hex2bin(hex: string): Uint8Array`

Converts a hex string to a byte array. Accepts an optional `0x` or `0X` prefix.
Odd-length hex strings are zero-padded on the right.

**Parameters:**
- `hex` — hex string (e.g. `'deadbeef'` or `'0xdeadbeef'`)

**Returns:** `Uint8Array`

---

#### `bin2hex(bin: Uint8Array, uppercase: boolean = false): string`

Converts a byte array to a hex string.

**Parameters:**
- `bin` — byte array
- `uppercase` — if `true`, output uses `A–F`; default is lowercase `a–f`

**Returns:** hex string with no prefix

---

#### `base642bin(base64: string): Uint8Array | undefined`

Decodes a standard base64 or base64url string. Uses the browser's native `atob` if
available; falls back to a pure-JS implementation in non-browser environments.

Base64url characters (`-` and `_`) are normalised to standard base64 (`+` and `/`)
before decoding. URL-encoded padding (`%3d`) is also accepted.

**Parameters:**
- `base64` — base64 or base64url encoded string

**Returns:** `Uint8Array`, or `undefined` if the input length is not a multiple of 4

---

#### `bin2base64(bin: Uint8Array, url: boolean = false): string`

Encodes a byte array as base64 or base64url. Uses the browser's native `btoa` if
available; falls back to a pure-JS implementation.

**Parameters:**
- `bin` — byte array
- `url` — if `true`, produces base64url encoding (`-`/`_` instead of `+`/`/`, `%3d` padding)

**Returns:** base64 (or base64url) encoded string

---

#### `int2bin(integer: number): Uint8Array`

Converts a 32-bit integer to a 4-byte little-endian array.

**Returns:** `Uint8Array(4)` — LSB first

---

#### `number2bin(value: number): Uint8Array`

Converts a number (integer or IEEE-754 double) to an 8-byte little-endian array.
Integers are encoded as int64 LE; floats/doubles are encoded as IEEE-754 double LE.

**Returns:** `Uint8Array(8)`

---

#### `bin2number(bin: Uint8Array): number`

Converts an 8-byte little-endian array back to a JavaScript number. Interprets the
bytes as a 64-bit little-endian integer.

**Parameters:**
- `bin` — exactly 8 bytes, LSB at index 0

**Returns:** `number`

---

#### `bin2longbin(bin: Uint8Array): Uint32Array`

Packs a byte array into 32-bit little-endian words.

**Returns:** `Uint32Array` of length `Math.floor(bin.length / 4)`

---

### `namespace Util`

#### `compare(lh: Uint8Array, rh: Uint8Array): boolean`

Constant-time array comparison. Delegates to `constantTimeEqual`. Use this or
`constantTimeEqual` directly whenever comparing secrets.

---

#### `clear(data: Uint8Array | Uint16Array | Uint32Array): void`

Zeroes all elements of the typed array in place. Use to wipe key material from
memory after use.

**Example:**
```typescript
import { Util } from 'leviathan';
const key = getKey();
// ... use key ...
Util.clear(key);  // zero the key bytes
```

---

#### `xor(lh: Uint8Array, rh: Uint8Array): Uint8Array`

Returns a new array containing `lh[i] ^ rh[i]` for each index. Does not modify
either input. Undefined behaviour if arrays differ in length (excess bytes from
`lh` are XOR'd with `undefined`, which becomes `NaN`, coercing to 0).

---

#### `concat(lh: Uint8Array, rh: Uint8Array): Uint8Array`

Returns a new array that is `lh` followed by `rh`.

---

#### `litteendian(): boolean`

Returns `true` if the host platform is little-endian.

---

## Usage Examples

### Format round-trips

```typescript
import { Convert } from 'leviathan';

// String ↔ binary
const bin = Convert.str2bin('Hello');
console.log(Convert.bin2str(bin));  // "Hello"

// Hex ↔ binary
const key = Convert.hex2bin('000102030405060708090a0b0c0d0e0f');
console.log(Convert.bin2hex(key));  // "000102030405060708090a0b0c0d0e0f"

// Base64 ↔ binary
const b64   = Convert.bin2base64(key);
const round = Convert.base642bin(b64);
```

### Constant-time MAC verification

```typescript
import { HMAC_SHA256, constantTimeEqual, Convert } from 'leviathan';

const hmac = new HMAC_SHA256();
const key  = Convert.hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
const msg  = Convert.str2bin('Test message');

const tag      = hmac.hash(key, msg);
const received = /* tag from network */tag;

// Safe comparison — prevents timing oracle
if (!constantTimeEqual(tag, received)) {
  throw new Error('Message authentication failed');
}
```

---

## Error Conditions

- **`base642bin` with invalid length:** Returns `undefined` if the input string length is
  not a multiple of 4. Check for `undefined` before using the result.
- **`hex2bin` with odd-length input:** Silently zero-pads the input on the right (`'abc'`
  becomes `'abc0'`). No exception is thrown.
- **`xor` with mismatched lengths:** No exception. Excess bytes from the longer array are
  XOR'd with `0` (due to JS typed-array out-of-bounds returning `undefined` which coerces
  to 0 in bitwise operations). Validate lengths before calling.
- **Null/undefined inputs:** Will throw a runtime `TypeError`.

---

## See Also

- [hmac.ts](./hmac.md) — uses `Util.compare` / `constantTimeEqual` internally
- [x25519.ts](./x25519.md) — uses `constantTimeEqual` for timing-safe signature verification
- [Wiki Home](./README.md) — library overview
