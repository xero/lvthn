# random.ts

Fortuna CSPRNG — cryptographically secure pseudo-random number generator with
multi-source entropy collection. [source](https://www.schneier.com/wp-content/uploads/2015/12/fortuna.pdf)

---

## Overview

`random.ts` exports a single class, `Random`, implementing a variant of Bruce Schneier
and Niels Ferguson's Fortuna CSPRNG. The generator combines:

- **Multiple entropy pools** (default 32, configurable down to 16 for constrained
  environments) that accumulate entropy from environmental sources.
- **Serpent-256 in counter mode** as the block cipher generating the keystream.
- **SHA-256** for pool hashing and key derivation during reseeds.

The generator auto-starts on construction and begins collecting entropy immediately.
The primary API is `get(length)`, which returns `length` cryptographically random bytes
or `undefined` if the generator has not yet been seeded (insufficient entropy).

**Entropy sources used:**

| Source | Browser | Node |
|--------|---------|------|
| `crypto.getRandomValues` | ✓ | — |
| `require('crypto').randomBytes` | — | ✓ |
| Mouse / click events | ✓ | — |
| Keyboard events | ✓ | — |
| Scroll / touch events | ✓ | — |
| Device motion / orientation | ✓ (mobile) | — |
| `performance.now()` timing | ✓ | ✓ |
| `process.hrtime()` | — | ✓ |
| DOM snapshot (innerHTML hash) | ✓ | — |
| Periodic `setInterval` | ✓ | ✓ |

---

## Security Notes

**`get()` may return `undefined`.** Until the generator has been seeded (pool 0 has
accumulated ≥ 64 bits of entropy AND 10 seconds have elapsed since construction), `get()`
returns `undefined`. In practice this is resolved almost immediately in environments with
`crypto.randomBytes` or `crypto.getRandomValues` — the constructor calls
`collectorCryptoRandom` multiple times synchronously. Always check the return value:

```typescript
const key = rng.get(32);
if (!key) throw new Error('PRNG not ready');
```

**Reseed trigger:** A reseed occurs when `poolEntropy[0] >= 64` bits AND at least 10,000
milliseconds have elapsed since the last reseed. The reseed interval prevents rapid
forced reseeds that could drain entropy faster than it is collected.

**Fortuna pool rotation:** On the N-th reseed, the pools included in the seed material
are those whose index i satisfies `(1 << i) & N`. Pool 0 is used on every reseed; pool 1
on every other reseed; pool 2 every 4th reseed; and so on. This ensures that a compromised
pool cannot permanently compromise the generator's output.

**Key erasure after each output:** After generating output, the generator immediately
rekeys by consuming two additional Serpent blocks to produce a fresh 32-byte generator
key. Previous output cannot be used to predict future output even if the internal state
is later compromised (forward secrecy property).

**External entropy injection:** Additional entropy from a hardware RNG or other trusted
source can be injected at any time via `addEntropy()`.

**Node.js usage note:** The `require('crypto')` call in `collectorCryptoRandom` is
dynamic. In bundled environments (Webpack, Rollup with Node polyfills disabled) this may
fail silently. If `get()` returns `undefined` unexpectedly, pass initial entropy to the
constructor.

---

## API Reference

### `class Random`

#### `constructor(numPools?: number, entropy?: Uint8Array)`

Initialises the generator, sets up entropy pools, seeds from available sources, and
starts periodic collectors.

**Parameters:**
- `numPools` — number of Fortuna entropy pools (default: 32; use 16 in entropy-constrained
  environments such as embedded/IoT)
- `entropy` — optional initial seed bytes from a trusted external source; more is better

**Example:**
```typescript
import { Random } from 'leviathan';

const rng = new Random();     // standard 32-pool Fortuna
const key = rng.get(32)!;     // 256-bit random key
```

---

#### `get(length: number): Uint8Array | undefined`

Returns `length` cryptographically secure random bytes, or `undefined` if the generator
has not yet accumulated sufficient entropy and been seeded.

**Parameters:**
- `length` — number of bytes to generate

**Returns:** `Uint8Array(length)`, or `undefined` if not yet seeded

**Example:**
```typescript
const key   = rng.get(32)!;   // 256-bit key
const iv    = rng.get(16)!;   // 128-bit IV
const nonce = rng.get(8)!;    // 64-bit nonce
```

---

#### `getEntropy(): number`

Returns the current accumulated entropy estimate in bytes.

**Returns:** `number` — approximate available entropy in bytes

---

#### `addEntropy(entropy: Uint8Array): void`

Injects external entropy into the accumulator pools.

**Parameters:**
- `entropy` — random bytes from a hardware RNG, OS entropy source, or other trusted provider

**Example:**
```typescript
import { Random } from 'leviathan';

// Provide initial entropy from a hardware RNG
const externalSeed = getHardwareRngBytes(64);
const rng = new Random(32, externalSeed);
```

---

#### `start(): void`

Reinitialises and starts the generator (calls `init()` internally). Normally not needed —
the constructor calls this automatically.

---

#### `stop(): void`

Stops the entropy collectors and clears the `setInterval` timer. Use if you need to
cleanly shut down the generator (e.g. in a long-running server process).

---

## Usage Examples

### Key and IV generation

```typescript
import { Random, Serpent_CBC_PKCS7, Convert } from 'leviathan';

const rng    = new Random();
const cipher = new Serpent_CBC_PKCS7();

const key = rng.get(32);   // may be undefined before first reseed
if (!key) throw new Error('RNG not ready');
const iv  = rng.get(16)!;

const ct = cipher.encrypt(key, Convert.str2bin('Secret payload'), iv);
```

---

### Seeding with external entropy (server-side)

```typescript
import { Random } from 'leviathan';
import { randomBytes } from 'crypto';

// Provide generous initial entropy from Node's crypto module
const seed = randomBytes(256);
const rng  = new Random(32, seed);
const key  = rng.get(32)!;
```

---

### Generating nonces for ChaCha20

```typescript
import { Random, ChaCha20 } from 'leviathan';

const rng    = new Random();
const chacha = new ChaCha20();

// Generate a fresh nonce for every message
const key   = rng.get(32)!;
const nonce = rng.get(8)!;   // 8-byte nonce for original ChaCha20

const ct = chacha.encrypt(key, plaintext, nonce);
// Store nonce alongside ciphertext for decryption
```

---

## Error Conditions

- **`get()` returns `undefined`:** Generator not yet seeded. Wait briefly (a few
  milliseconds in Node, nearly instant due to `crypto.randomBytes`), or pass initial
  entropy to the constructor. In browsers without events, poll `getEntropy()` until
  sufficiently seeded.
- **`stop()` then `get()`:** After `stop()`, `this.active` is `false`. `get()` returns
  `undefined`. Call `start()` to restart the collector and wait for reseeding.
- **`numPools = 0`:** The pool arrays are empty; `get()` will attempt to iterate 0 pools
  and never trigger a reseed. Do not pass 0.

---

## See Also

- [serpent.ts](./serpent.md) — Serpent-256 used as the Fortuna block cipher generator
- [sha256.ts](./sha256.md) — SHA-256 used for pool hashing and key derivation in Fortuna
- [Wiki Home](./README.md) — library overview
