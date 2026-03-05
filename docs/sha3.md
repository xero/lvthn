# sha3.ts

SHA-3 family — Keccak sponge construction: SHA3-256/384/512, Keccak-256/384/512, SHAKE128, SHAKE256.

---

## Overview

`sha3.ts` exports eight classes based on the Keccak sponge construction. SHA-3 was
standardised by NIST in FIPS 202 (2015). The Keccak variants use the original Keccak
padding; the SHA3 variants use the NIST-standard domain separation byte. SHAKE128 and
SHAKE256 are extendable-output functions (XOFs) that produce an arbitrary-length output.

All classes extend the `Keccak` base class, which implements the Keccak-f[1600] permutation
and the sponge absorb/squeeze cycle. The state is a 5×5 array of 64-bit words represented
as 50 × 32-bit `Uint32Array` entries (high/low pairs).

| Class | Capacity (bits) | Padding | Output size |
|-------|----------------|---------|-------------|
| `Keccak_256` | 256 | 0x01 | 32 bytes |
| `Keccak_384` | 384 | 0x01 | 48 bytes |
| `Keccak_512` | 512 | 0x01 | 64 bytes |
| `SHA3_256` | 256 | 0x06 | 32 bytes |
| `SHA3_384` | 384 | 0x06 | 48 bytes |
| `SHA3_512` | 512 | 0x06 | 64 bytes |
| `SHAKE128` | 128 | 0x1F | caller-specified |
| `SHAKE256` | 256 | 0x1F | caller-specified |

**SHA3 vs Keccak:** The SHA3 classes use NIST's domain separation byte (0x06) and are
compatible with FIPS 202 vectors. The Keccak classes use the original Keccak padding byte
(0x01) from before the NIST standardisation and are compatible with the Ethereum `keccak256`
hash. **They are not interchangeable.** Use `SHA3_256` for FIPS compliance, `Keccak_256`
for Ethereum compatibility.

---

## Security Notes

**Keccak vs SHA3 padding is a real difference.** Many blockchain and smart-contract
applications use the pre-NIST Keccak padding (0x01). FIPS 202 SHA-3 uses 0x06. The two
produce different digests for all inputs. Check which variant your interoperability
target expects.

**SHAKE output length is caller-controlled.** SHAKE128 and SHAKE256 accept a `length`
parameter (in bits) at construction time. The security level of SHAKE128 is min(capacity/2,
output_bits/2) = min(64, output_bits/2). For outputs ≥ 128 bits, SHAKE128 provides 64
bits of security. SHAKE256 provides min(128, output_bits/2) bits.

**State is little-endian internally.** The Keccak-f[1600] state words are stored and
absorbed in little-endian byte order. The `digest()` serialisation reads state words as
little-endian 32-bit words. This is correct per the Keccak specification.

**State is reset after `digest()`.** As with `SHA256` and `SHA512`, `digest()` calls
`init()` before returning, leaving the instance ready for reuse.

**`selftest()` uses SHA3-256.** The self-test in the `Keccak` base class instantiates
`SHA3_256` directly for its accumulation loop. Passing the self-test verifies only
`SHA3_256` correctness, not the other variants. The Vitest suite tests all variants
against known vectors.

---

## API Reference

### `class Keccak`

Base class implementing the Keccak sponge. Parameterised by capacity, padding byte, and
output length.

#### `constructor(bits: number, padding: number, length?: number)`

**Parameters:**
- `bits` — capacity in bits (256, 384, or 512); determines the rate: `rate = 1600 − 2×bits`
- `padding` — domain separation byte (0x01 for Keccak, 0x06 for SHA-3, 0x1F for SHAKE)
- `length` — output length in bits; defaults to `bits` if omitted (used by SHAKE)

---

#### `init(): Keccak`

Zeroes the 50-word state array, clears the buffer, and resets the buffer index.

**Returns:** `this` (chainable)

---

#### `update(msg?: Uint8Array): Keccak`

Feeds message bytes into the sponge absorb phase. Processes full blocks (rate / 8 bytes)
as they accumulate; partial blocks remain buffered.

**Parameters:**
- `msg` — message bytes; defaults to empty if omitted

**Returns:** `this` (chainable)

---

#### `digest(msg?: Uint8Array): Uint8Array`

Finalises the hash: appends the domain separation byte, applies the 0x80 multi-rate
padding terminator, runs the final Keccak-f permutation, and extracts `hashSize` bytes
from the state in little-endian word order.

Calls `init()` before returning.

**Parameters:**
- `msg` — optional final message chunk; defaults to empty if omitted

**Returns:** `Uint8Array(hashSize)`

---

#### `hash(msg?: Uint8Array): Uint8Array`

One-shot method. Calls `init()` then `digest(msg)`.

**Parameters:**
- `msg` — complete message; defaults to empty if omitted

**Returns:** `Uint8Array(hashSize)`

---

#### `selftest(): boolean`

Runs a 1000-iteration accumulating self-test using SHA3-256. Returns `true` if correct.

---

### Concrete subclasses

#### `class Keccak_256`

Pre-NIST Keccak, 256-bit output. Padding byte 0x01. Compatible with Ethereum `keccak256`.

```typescript
import { Keccak_256 } from 'leviathan';
const hash = new Keccak_256().hash(msg);  // 32 bytes
```

---

#### `class Keccak_384`

Pre-NIST Keccak, 384-bit output. Padding byte 0x01.

---

#### `class Keccak_512`

Pre-NIST Keccak, 512-bit output. Padding byte 0x01.

---

#### `class SHA3_256`

FIPS 202 SHA3-256. Padding byte 0x06. 32-byte output.

```typescript
import { SHA3_256 } from 'leviathan';
const hash = new SHA3_256().hash(msg);  // 32 bytes
```

---

#### `class SHA3_384`

FIPS 202 SHA3-384. Padding byte 0x06. 48-byte output.

---

#### `class SHA3_512`

FIPS 202 SHA3-512. Padding byte 0x06. 64-byte output.

---

#### `class SHAKE128`

Extendable-output function, capacity 128 bits. Padding byte 0x1F.

#### `constructor(length: number)`

**Parameters:**
- `length` — desired output length **in bits** (e.g. `256` for 32 bytes)

```typescript
import { SHAKE128 } from 'leviathan';
const hash = new SHAKE128(256).hash(msg);  // 32 bytes
```

---

#### `class SHAKE256`

Extendable-output function, capacity 256 bits. Padding byte 0x1F.

#### `constructor(length: number)`

**Parameters:**
- `length` — desired output length **in bits**

```typescript
import { SHAKE256 } from 'leviathan';
const hash = new SHAKE256(512).hash(msg);  // 64 bytes
```

---

## Usage Examples

### SHA3-256 one-shot

```typescript
import { SHA3_256, Convert } from 'leviathan';

const sha3 = new SHA3_256();
const hash = sha3.hash(Convert.str2bin('Hello, world!'));
console.log(Convert.bin2hex(hash));  // 32-byte SHA3-256 digest
```

---

### Keccak-256 (Ethereum-compatible)

```typescript
import { Keccak_256, Convert } from 'leviathan';

const keccak = new Keccak_256();
const hash   = keccak.hash(Convert.str2bin('some data'));
// Compatible with Ethereum's keccak256 precompile
```

---

### SHAKE128 with custom output length

```typescript
import { SHAKE128, Convert } from 'leviathan';

// 64-byte (512-bit) output
const shake = new SHAKE128(512);
const output = shake.hash(Convert.str2bin('input data'));
console.log(output.length);  // 64
```

---

### Incremental SHA3-512

```typescript
import { SHA3_512, Convert } from 'leviathan';

const sha3 = new SHA3_512();
sha3.update(Convert.str2bin('chunk one'));
sha3.update(Convert.str2bin('chunk two'));
const hash = sha3.digest();
```

---

## Error Conditions

- **SHAKE `length` not a multiple of 32:** The `digest()` loop reads `hashSize / 4` words
  from the state. If `length` (in bits) is not a multiple of 32, `hashSize / 4` will not
  be an integer, causing incorrect output. Always pass `length` values divisible by 32
  (i.e. output lengths that are multiples of 4 bytes).
- **`update()` after `digest()`:** `digest()` resets state via `init()`. Subsequent
  `update()` calls begin a new hash. This is valid but potentially unexpected.
- **Null/undefined inputs:** Will throw a runtime `TypeError`.

---

## See Also

- [sha256.ts](./sha256.md) — SHA-256 (Merkle-Damgård construction)
- [sha512.ts](./sha512.md) — SHA-512 (Merkle-Damgård construction)
- [hmac.ts](./hmac.md) — HMAC (usable with any `Hash`, including SHA3 variants)
- [index.ts](./index.md) — library overview
