# argon2id.ts

Argon2id — memory-hard password hashing and key derivation (RFC 9106).

> **Recommended replacement for PBKDF2.** Argon2id is memory-hard: each
> password guess must allocate and fill a large RAM buffer, making GPU/ASIC
> brute-force attacks orders of magnitude more expensive than CPU-only KDFs
> like PBKDF2. For all new implementations, use Argon2id instead of PBKDF2.
>
> See [pbkdf2.md](./pbkdf2.md) for the migration path from PBKDF2.

---

## Overview

`argon2id.ts` provides the `Argon2id` class, three named parameter presets,
and supporting types for integrating Argon2id password hashing and key
derivation into leviathan applications.

**Underlying package:** `argon2id@1.0.1` by the OpenPGP.js team — a
WASM-based, RFC 9106-compliant implementation with zero runtime dependencies.

**Environment:** This wrapper targets Node.js (19+) and Bun. It loads the
WASM binary directly from disk via `readFileSync`. Browser support requires a
bundler (e.g. Vite, Webpack) that can handle `.wasm` imports — the
`node:fs`-based loader is not browser-compatible. See the
[Browser Compatibility](#browser-compatibility) section below.

**Audit:** The `argon2id` npm package is maintained by the OpenPGP.js team,
whose core library was audited by Cure53 in 2019. The `argon2id` package
itself does not have an independent published audit as of its 1.0.1 release.
See: https://github.com/openpgpjs/argon2id

---

## What is Memory-Hardness?

PBKDF2 is *compute-bound*: its work factor scales only with CPU time.
An attacker with a GPU can run thousands of PBKDF2 attempts in parallel
cheaply, because each attempt requires only CPU cycles.

Argon2id is *memory-hard*: each attempt must allocate and fill a large RAM
buffer (e.g. 19 MiB with `ARGON2ID_INTERACTIVE`). GPUs have limited per-core
SRAM — filling 19 MiB per attempt forces each GPU core to wait for DRAM
accesses, eliminating the parallel speedup that makes GPU attacks cheap.

The practical effect: with the `ARGON2ID_INTERACTIVE` preset, an attacker
with a high-end GPU gains less than an order of magnitude speedup over a
single CPU core, compared to PBKDF2 where a GPU might run 10,000× faster.

---

## Security Notes

**Store hash + salt + params together.** All three are required to verify
a password or re-derive a key. Losing the salt makes the hash permanently
unverifiable.

**Salt must be unique per password.** The salt is not secret but must be
random and never reused. `Argon2id.hash()` generates a random salt
automatically via `crypto.getRandomValues` when none is provided.

**`verify()` uses constant-time comparison.** The implementation calls
`constantTimeEqual` (XOR-accumulate, visits every byte regardless of
content) to compare the recomputed hash against the stored hash. This
prevents timing oracle attacks. Never use `===` or `Buffer.equals()` to
compare Argon2id outputs directly.

**Choose presets based on your latency budget.** For interactive logins,
aim for 0.5–1 second per hash on your target hardware. Benchmark the
presets on your deployment environment and adjust `memoryCost` or
`timeCost` if needed (see [Parameter Tuning](#parameter-tuning)).

**HMAC-before-decrypt pattern.** When using `deriveKey()` for encryption,
always verify the HMAC over the ciphertext *before* attempting decryption,
as the leviathan LVTHN format does. This prevents chosen-ciphertext attacks
and avoids leaking information through decryption errors.

---

## Presets

Three named presets are provided. Use presets rather than raw numbers.

### `ARGON2ID_INTERACTIVE`

```typescript
{
  memoryCost:  19456,  // 19 MiB — OWASP 2023 minimum
  timeCost:    2,      // 2 passes
  parallelism: 1,      // 1 thread
  saltLength:  32,     // 32-byte salt
  hashLength:  32,     // 32-byte output
}
```

**When to use:** Most interactive applications — login forms, API key
derivation, session tokens. Typically 50–200 ms on modern server hardware.
This is the default for `Argon2id.hash()` and `Argon2id.verify()`.

Source: [OWASP Password Storage Cheat Sheet 2023](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### `ARGON2ID_SENSITIVE`

```typescript
{
  memoryCost:  65536,  // 64 MiB — OWASP 2023 high-security
  timeCost:    3,      // 3 passes
  parallelism: 4,      // 4 threads
  saltLength:  32,
  hashLength:  32,
}
```

**When to use:** High-value accounts, passphrase-protected key escrow,
root credentials, or any context where 200 ms–1 second per hash is
acceptable. Requires 64 MiB of RAM per concurrent hash operation.

Source: [OWASP Password Storage Cheat Sheet 2023](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### `ARGON2ID_DERIVE`

```typescript
{
  ...ARGON2ID_INTERACTIVE,   // same parameters
  hashLength: 32,            // always 256-bit for key derivation
}
```

**When to use:** Deriving Serpent encryption keys from passphrases. Same
security parameters as `ARGON2ID_INTERACTIVE`; the distinct name clarifies
intent. Used by `deriveKey()` automatically.

---

## API Reference

### `class Argon2id`

#### `hash(password, salt?, params?): Promise<Argon2idResult>`

Hash a password or derive a key from a passphrase.

**Parameters:**
- `password` — plaintext password (string or Uint8Array). Strings are
  UTF-8 encoded automatically.
- `salt` — optional. If omitted, a random salt of `params.saltLength` bytes
  is generated via `crypto.getRandomValues`. Always store the returned salt.
- `params` — optional. Defaults to `ARGON2ID_INTERACTIVE`.

**Returns:** `Promise<Argon2idResult>` with `hash`, `salt`, and `params`.

**Example:**
```typescript
const argon2 = new Argon2id();
const { hash, salt, params } = await argon2.hash('correct horse battery staple');
// store hash, salt, params in the database
```

---

#### `verify(password, hash, salt, params?): Promise<boolean>`

Verify a password against a previously computed hash.

Recomputes the hash with the provided salt and params, then compares using
`constantTimeEqual`. Returns `true` if the password matches.

**Parameters:**
- `password` — plaintext password to verify
- `hash` — previously stored hash (from `Argon2idResult.hash`)
- `salt` — previously stored salt (from `Argon2idResult.salt`)
- `params` — previously stored parameters. Defaults to `ARGON2ID_INTERACTIVE`.

**Example:**
```typescript
const ok = await argon2.verify(inputPassword, storedHash, storedSalt, storedParams);
if (!ok) throw new Error('Authentication failed');
```

---

#### `deriveKey(passphrase, salt?, keyLength?): Promise<{ key, salt }>`

Derive a fixed-length encryption key from a passphrase.

Uses `ARGON2ID_DERIVE` parameters. The returned key is directly usable as
a Serpent-256 key (16, 24, or 32 bytes).

**Parameters:**
- `passphrase` — source passphrase (string or Uint8Array)
- `salt` — optional. Generated randomly if omitted. Store it with ciphertext.
- `keyLength` — 16, 24, or 32 bytes (default: 32)

**Returns:** `Promise<{ key: Uint8Array; salt: Uint8Array }>`

**Example:**
```typescript
const { key, salt } = await new Argon2id().deriveKey('my passphrase');
// salt is not secret — store it alongside the ciphertext
```

---

### Types

#### `interface Argon2idParams`

```typescript
interface Argon2idParams {
  memoryCost:  number  // RAM in KiB
  timeCost:    number  // passes over memory
  parallelism: number  // lanes / threads
  saltLength:  number  // salt length in bytes
  hashLength:  number  // output length in bytes
}
```

#### `interface Argon2idResult`

```typescript
interface Argon2idResult {
  hash:   Uint8Array      // raw Argon2id output
  salt:   Uint8Array      // salt used
  params: Argon2idParams  // parameters used
}
```

---

## Usage Examples

### Password hashing and verification

```typescript
import { Argon2id, ARGON2ID_INTERACTIVE } from 'leviathan';

const argon2 = new Argon2id();

// On registration — hash and store
const { hash, salt, params } = await argon2.hash(userPassword);
await db.saveCredentials(userId, { hash, salt, params });

// On login — load stored values and verify
const stored = await db.loadCredentials(userId);
const ok = await argon2.verify(
  inputPassword,
  stored.hash,
  stored.salt,
  stored.params,
);
if (!ok) throw new Error('Authentication failed');
```

### Passphrase → encryption key → Serpent encryption (full workflow)

```typescript
import {
  Argon2id, ARGON2ID_DERIVE,
  Serpent_CBC_PKCS7, HMAC_SHA256,
  Convert,
} from 'leviathan';

async function encrypt(plaintext: Uint8Array, passphrase: string) {
  const argon2 = new Argon2id();

  // Derive a 256-bit key from the passphrase
  const { key, salt } = await argon2.deriveKey(passphrase);

  // Random IV for Serpent-CBC
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);

  // Encrypt
  const cipher = new Serpent_CBC_PKCS7();
  const ciphertext = cipher.encrypt(key, plaintext, iv);

  // Authenticate: HMAC-SHA256 over (salt + iv + ciphertext)
  const payload = new Uint8Array(salt.length + iv.length + ciphertext.length);
  payload.set(salt, 0);
  payload.set(iv, salt.length);
  payload.set(ciphertext, salt.length + iv.length);

  const hmac = new HMAC_SHA256();
  const tag = hmac.hash(key, payload);

  // Persist: salt + iv + tag + ciphertext
  return { salt, iv, tag, ciphertext };
}

async function decrypt(
  bundle: { salt: Uint8Array; iv: Uint8Array; tag: Uint8Array; ciphertext: Uint8Array },
  passphrase: string,
) {
  const argon2 = new Argon2id();

  // Re-derive the same key using the stored salt
  const { key } = await argon2.deriveKey(passphrase, bundle.salt);

  // Verify HMAC before decrypting (authenticated encryption pattern)
  const payload = new Uint8Array(
    bundle.salt.length + bundle.iv.length + bundle.ciphertext.length,
  );
  payload.set(bundle.salt, 0);
  payload.set(bundle.iv, bundle.salt.length);
  payload.set(bundle.ciphertext, bundle.salt.length + bundle.iv.length);

  const hmac = new HMAC_SHA256();
  const expectedTag = hmac.hash(key, payload);

  // Constant-time tag comparison — prevents timing oracle
  const { constantTimeEqual } = await import('./base');
  if (!constantTimeEqual(bundle.tag, expectedTag)) {
    throw new Error('Authentication failed');
  }

  // Decrypt
  const cipher = new Serpent_CBC_PKCS7();
  return cipher.decrypt(key, bundle.ciphertext, bundle.iv);
}
```

### Using the high-security preset for sensitive credentials

```typescript
import { Argon2id, ARGON2ID_SENSITIVE } from 'leviathan';

const argon2 = new Argon2id();
const { hash, salt, params } = await argon2.hash(
  adminPassword,
  undefined,
  ARGON2ID_SENSITIVE,  // 64 MiB, 3 passes — ~500 ms on server hardware
);
```

---

## Parameter Tuning

If neither `ARGON2ID_INTERACTIVE` nor `ARGON2ID_SENSITIVE` fits your
performance budget, tune parameters manually:

1. **Start with `memoryCost`:** Higher memory is more valuable than higher
   `timeCost` for resistance against GPU attacks. Aim for as much RAM as you
   can spare per concurrent request.

2. **Increase `timeCost` to hit your latency target:** After fixing
   `memoryCost`, increase `timeCost` from 1 upward until hashing takes
   approximately your target duration (0.5–1 second for interactive logins).

3. **Leave `parallelism` at 1** unless you have profiled that Argon2id is
   CPU-bound on your hardware. Higher `parallelism` allocates `p × memoryCost`
   KiB total and may not improve throughput in server contexts where many
   requests compete for CPU.

4. **Benchmark on target hardware.** Cloud VMs and developer laptops have
   very different memory bandwidth. Always measure before deploying.

```typescript
// Example: custom parameters tuned to ~500 ms on a 4-core cloud instance
const customParams: Argon2idParams = {
  memoryCost:  32768,  // 32 MiB
  timeCost:    3,
  parallelism: 1,
  saltLength:  32,
  hashLength:  32,
};
```

---

## What to Store

When hashing passwords for authentication, persist all three fields:

| Field | Required for verification? | Secret? |
|-------|---------------------------|---------|
| `hash` | yes | yes |
| `salt` | yes | no |
| `params` | yes | no |

Storing `params` alongside the hash allows you to upgrade parameters later:
on a successful login with old params, re-hash immediately with new params.

---

## Browser Compatibility

The `argon2id.ts` wrapper uses `readFileSync` from `node:fs` to load the
WASM binary, which is **not available in browsers**.

For browser environments:
- Use a bundler (Vite, Webpack) that resolves `.wasm` imports natively.
- Import from `argon2id` directly (e.g. `import { loadWasm } from 'argon2id'`)
  and handle WASM loading with `WebAssembly.instantiateStreaming`.
- Alternatively, use the browser's `SubtleCrypto.deriveKey` API with
  PBKDF2 (available natively, no WASM required) for web-only applications
  that cannot use a bundler.

The `lvthn-web` demo app uses the browser's native `SubtleCrypto` PBKDF2
API rather than this Argon2id wrapper, because the demo is a single-file
HTML page with no build step and no bundler.

---

## Error Conditions

| Condition | Error message |
|-----------|---------------|
| `memoryCost < 8` | `Argon2id: memoryCost must be >= 8 KiB (got N)` |
| `timeCost < 1` | `Argon2id: timeCost must be >= 1 (got N)` |
| `parallelism < 1` | `Argon2id: parallelism must be >= 1 (got N)` |
| `hashLength < 4` | `Argon2id: hashLength must be >= 4 bytes (got N)` |
| `saltLength < 8` | `Argon2id: saltLength must be >= 8 bytes (got N)` |

Validation is performed by `validateParams()` before any WASM call, so
parameter errors are thrown synchronously within the returned Promise.

---

## See Also

- [pbkdf2.md](./pbkdf2.md) — deprecated KDF; migration path to Argon2id
- [serpent.md](./serpent.md) — Serpent-256 cipher for key derivation usage
- [hmac.md](./hmac.md) — HMAC-SHA256 for authenticated encryption
- [base.md](./base.md) — `constantTimeEqual` used in `verify()`
- [serpent_audit.md](./serpent_audit.md) — full cryptographic audit report
- RFC 9106: https://www.rfc-editor.org/rfc/rfc9106
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Package source: https://github.com/openpgpjs/argon2id
