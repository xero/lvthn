# hmac.ts

HMAC — Hash-based Message Authentication Code, parameterised by any `Hash` implementation.

---

## Overview

`hmac.ts` exports three classes:

| Class | Underlying hash | Output size |
|-------|----------------|-------------|
| `HMAC` | Any `Hash` (constructor parameter) | Varies (matches hash) |
| `HMAC_SHA256` | SHA-256 | 32 bytes |
| `HMAC_SHA512` | SHA-512 | 64 bytes |

HMAC is a MAC construction defined in RFC 2104. It provides message integrity and
authentication: given a shared secret key, a sender produces a tag over a message; a
receiver re-derives the tag and compares it to verify that the message was not tampered
with and came from a party that knows the key.

**Recommended usage:** Use `HMAC_SHA256` or `HMAC_SHA512` for all new code. Use the
`hash()` one-shot method for most cases; use `init()`/`update()`/`digest()` only when
the message is delivered incrementally (e.g. streaming).

---

## Security Notes

**Tag comparison must use `constantTimeEqual`.** Never compare HMAC tags with `===` or
`Array.prototype.every`. Ordinary comparison short-circuits on the first differing byte,
enabling timing-oracle attacks (byte-at-a-time HMAC forgery). Always compare with
`constantTimeEqual` or `Util.compare`:

```typescript
import { HMAC_SHA256, constantTimeEqual } from 'leviathan';
const mac = new HMAC_SHA256();
const expected = mac.hash(key, msg);
const received = /* tag from network */;
if (!constantTimeEqual(expected, received)) {
  throw new Error('MAC verification failed');
}
```

**Block size selection follows RFC 4868:** When the underlying hash output size is ≤ 32
bytes (SHA-256 and smaller), the HMAC block size `B` is 64 bytes. When the hash output
size is > 32 bytes (SHA-512), `B` is 128 bytes.

**Key length:** Keys longer than `B` are hashed down to `hashSize` bytes before use. Keys
shorter than `B` are zero-padded to `B`. Using a key shorter than `hashSize` reduces
security — always use a key of at least `hashSize` bytes (32 bytes for HMAC-SHA256, 64
bytes for HMAC-SHA512). Generate keys with `Random.get()`.

**Key erasure:** The key material is zeroed (`Util.clear`) inside `init()` after the
inner and outer key pads are derived. The iKeyPad and oKeyPad copies persist on the
object for the duration of the computation; they are not automatically cleared after
`digest()`. If you need to erase after use, clear `hmac.iKeyPad` and `hmac.oKeyPad`
manually.

**`selftest()` always returns `false`:** The base `HMAC` class has a stub `selftest()`
that returns `false`. This is a known gap. Do not rely on `selftest()` for correctness
validation — use the test vectors in `test/spec/13_hmac.test.ts` instead.

---

## API Reference

### `class HMAC`

Generic HMAC parameterised by a `Hash` implementation. Implements the `KeyedHash`
interface.

#### `constructor(hasher: Hash)`

**Parameters:**
- `hasher` — any object implementing the `Hash` interface (`hashSize`, `init`, `update`,
  `digest`)

**Example:**
```typescript
import { HMAC } from 'leviathan';
import { SHA256 } from 'leviathan';

const hmac = new HMAC(new SHA256());
```

---

#### `init(key: Uint8Array): HMAC`

Initialises the HMAC with a key. Must be called before `update()` or `digest()`.

Computes the inner key pad (key XOR 0x36 repeated) and outer key pad (key XOR 0x5C
repeated), starts the inner hash with the inner key pad. Keys longer than `B` are
shortened by hashing; shorter keys are zero-padded to `B`.

**Parameters:**
- `key` — secret key (`Uint8Array`, any length)

**Returns:** `this` (chainable)

---

#### `update(msg?: Uint8Array): HMAC`

Feeds additional message data into the inner hash. May be called multiple times.

**Parameters:**
- `msg` — message chunk; defaults to an empty array if omitted

**Returns:** `this` (chainable)

---

#### `digest(msg?: Uint8Array): Uint8Array`

Finalises the HMAC and returns the authentication tag. An optional final message chunk
can be provided.

**Parameters:**
- `msg` — final message chunk; defaults to an empty array if omitted

**Returns:** `Uint8Array` of length `hashSize`

---

#### `hash(key: Uint8Array, msg?: Uint8Array): Uint8Array`

One-shot convenience method. Equivalent to `this.init(key).digest(msg)`.

**Parameters:**
- `key` — secret key
- `msg` — complete message; defaults to empty if omitted

**Returns:** `Uint8Array` of length `hashSize`

**Example:**
```typescript
import { HMAC_SHA256, Convert } from 'leviathan';

const mac = new HMAC_SHA256();
const key = Convert.hex2bin('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
const msg = Convert.str2bin('Hi There');
const tag = mac.hash(key, msg);
console.log(Convert.bin2hex(tag));
// b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
```

---

#### `selftest(): boolean`

Always returns `false` in the base class (stub; not implemented). Use the Vitest suite
instead.

---

### `class HMAC_SHA256`

Convenience subclass: `HMAC` with SHA-256 as the underlying hash.

- Output size: 32 bytes
- Block size `B`: 64 bytes (per RFC 4868)

#### `constructor()`

No parameters.

**Example:**
```typescript
import { HMAC_SHA256 } from 'leviathan';
const mac = new HMAC_SHA256();
```

---

### `class HMAC_SHA512`

Convenience subclass: `HMAC` with SHA-512 as the underlying hash.

- Output size: 64 bytes
- Block size `B`: 128 bytes (per RFC 4868)

#### `constructor()`

No parameters.

**Example:**
```typescript
import { HMAC_SHA512 } from 'leviathan';
const mac = new HMAC_SHA512();
```

---

## Usage Examples

### One-shot authentication (HMAC-SHA256)

```typescript
import { HMAC_SHA256, constantTimeEqual, Convert, Random } from 'leviathan';

const rng = new Random();
const mac = new HMAC_SHA256();

// Sender
const key = rng.get(32)!;  // 256-bit key — at least hashSize bytes
const msg = Convert.str2bin('Authenticated payload');
const tag = mac.hash(key, msg);

// Receiver — re-derive tag and compare in constant time
const expected = mac.hash(key, msg);
if (!constantTimeEqual(tag, expected)) {
  throw new Error('Message authentication failed');
}
```

---

### Streaming usage (large or chunked messages)

```typescript
import { HMAC_SHA512, Convert } from 'leviathan';

const mac = new HMAC_SHA512();
const key = Convert.hex2bin('...');  // 64-byte key recommended for SHA-512

mac.init(key);
mac.update(Convert.str2bin('chunk one'));
mac.update(Convert.str2bin('chunk two'));
mac.update(Convert.str2bin('chunk three'));
const tag = mac.digest();  // finalise with no extra data
```

---

### Using the generic HMAC class with SHA-3

```typescript
import { HMAC, SHA3 } from 'leviathan';

const sha3 = new SHA3(256);
const mac  = new HMAC(sha3);
const tag  = mac.hash(key, msg);  // HMAC-SHA3-256
```

---

## Error Conditions

- **`selftest()` returns `false`:** This is not an error; the method is a stub. It does
  not indicate implementation failure. Use the test suite to validate correctness.
- **Key shorter than `hashSize`:** No exception. The key is zero-padded. This is valid
  per RFC 2104 but reduces the effective security margin.
- **`init()` not called before `update()`/`digest()`:** `iKeyPad` and `oKeyPad` will be
  `undefined`, causing a `TypeError` at runtime. Always call `init()` first.
- **Null/undefined inputs:** Will throw a runtime `TypeError`.

---

## See Also

- [sha256.ts](./sha256.md) — SHA-256 hash used by `HMAC_SHA256`
- [sha512.ts](./sha512.md) — SHA-512 hash used by `HMAC_SHA512`
- [base.ts](./base.md) — `constantTimeEqual` and `Util.compare` for safe tag comparison
- [random.ts](./random.md) — CSPRNG for generating HMAC keys
- [index.ts](./index.md) — library overview
