# uuid.ts

UUID generation — V1 (time-based) and V4 (random-based) per RFC 4122.

> **Deprecated.** UUID generation is out of scope for a cryptographic library. For new
> code, use the platform's native `crypto.randomUUID()` (available in all modern browsers
> and Node.js 14.17+). This module is retained for backwards compatibility only.

---

## Overview

`uuid.ts` exports a single class, `UUID`, generating 128-bit universally unique
identifiers per RFC 4122. Two versions are supported:

- **V1** — time-based UUID. Encodes a timestamp (Gregorian epoch, 100-nanosecond
  resolution), a clock sequence (to handle clock regressions), and a 6-byte node
  identifier (typically a MAC address or random bytes).

- **V4** — random-based UUID. Takes 16 random bytes and sets the version and variant
  bits.

Both methods return a 16-byte `Uint8Array`, not a string. Use `toString()` to format
as the canonical `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` representation.

---

## Security Notes

**V1 UUIDs are not suitable as secrets.** The timestamp and node components are
predictable. An attacker who knows the approximate time a V1 UUID was generated and
the node identifier (often a MAC address) can reconstruct the UUID or narrow the search
space significantly. Never use V1 UUIDs as session tokens, CSRF tokens, or any
security-sensitive identifier.

**V4 UUIDs are only as random as their input.** `v4()` accepts 16 bytes of caller-supplied
random data. The randomness quality of the output depends entirely on the quality of the
input. Always use `Random.get(16)` to generate the input bytes. Do not use `Math.random()`
or predictable values.

**`clockseq` initialisation in V1 uses `Math.random()`.** When no `clockseq` parameter
is passed to `v1()`, the clock sequence is initialised from `Math.random()`, which is
not cryptographically secure. This is acceptable for the clock sequence (a collision
avoidance value), but it reinforces that V1 UUIDs are not appropriate for security use.

---

## API Reference

### `class UUID`

> **Deprecated.** Use `crypto.randomUUID()` for new code.

#### `constructor()`

No parameters. Initialises timestamp and clock sequence state.

---

#### `v1(node: Uint8Array, clockseq?: Uint8Array): Uint8Array | undefined`

Generates a time-based V1 UUID.

**Parameters:**
- `node` — exactly 6 bytes identifying the node; use a MAC address or `Random.get(6)`
  for a random node ID
- `clockseq` — optional 2-byte clock sequence seed; if omitted, initialised from
  `Math.random()`

**Returns:** `Uint8Array(16)` — 16-byte UUID with version bits set to V1 and variant
bits set per RFC 4122, or `undefined` if `node.length !== 6`

**Example:**
```typescript
import { UUID, Random } from 'leviathan';

const rng  = new Random();
const uuid = new UUID();

const node   = rng.get(6)!;   // random node ID (no MAC address exposed)
const result = uuid.v1(node);
if (result) {
  console.log(uuid.toString(result));
  // e.g. "7d444840-9dc0-11d1-b245-5ffdce74fad2"
}
```

---

#### `v4(rand: Uint8Array): Uint8Array | undefined`

Generates a random-based V4 UUID from 16 random bytes.

**Parameters:**
- `rand` — exactly 16 bytes of cryptographically random data

**Returns:** `Uint8Array(16)` — 16-byte UUID with version bits set to V4 and variant
bits set per RFC 4122, or `undefined` if `rand.length !== 16`

**Example:**
```typescript
import { UUID, Random } from 'leviathan';

const rng  = new Random();
const uuid = new UUID();

const rand   = rng.get(16)!;
const result = uuid.v4(rand);
if (result) {
  console.log(uuid.toString(result));
  // e.g. "110e8400-e29b-41d4-a716-446655440000"
}
```

---

#### `toString(uuid: Uint8Array): string`

Converts a 16-byte UUID to the canonical string format
`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.

**Parameters:**
- `uuid` — 16-byte UUID byte array

**Returns:** `string` in the format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, or
`'UUID format error'` if `uuid.length !== 16`

---

## Usage Examples

### V4 UUID (recommended for random IDs)

```typescript
import { UUID, Random } from 'leviathan';

const rng  = new Random();
const uuid = new UUID();

function generateId(): string {
  const rand = rng.get(16);
  if (!rand) throw new Error('RNG not ready');
  const u = uuid.v4(rand);
  if (!u) throw new Error('UUID generation failed');
  return uuid.toString(u);
}

console.log(generateId());  // "550e8400-e29b-41d4-a716-446655440000"
```

---

### Modern alternative (preferred)

```typescript
// Use the Web Crypto API instead — no dependency needed
const id = crypto.randomUUID();
console.log(id);  // "110e8400-e29b-41d4-a716-446655440000"
```

---

## Error Conditions

- **`v1()` with `node.length !== 6`:** Returns `undefined`. Always validate the return
  value before use.
- **`v4()` with `rand.length !== 16`:** Returns `undefined`. Always validate the return
  value before use.
- **`toString()` with `uuid.length !== 16`:** Returns the string `'UUID format error'`
  rather than throwing. Check the return value if the input length is not guaranteed.

---

## See Also

- [random.ts](./random.md) — CSPRNG for generating random bytes for V4 UUIDs
- [index.ts](./index.md) — library overview and deprecation context
