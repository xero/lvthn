# pbkdf2.ts

PBKDF2 — Password-Based Key Derivation Function 2 (RFC 2898).

> **Deprecated.** PBKDF2 has low memory hardness and is vulnerable to GPU/ASIC
> brute-force attacks. For new code, use **Argon2id** or **scrypt**. PBKDF2 is retained
> for compatibility with existing systems only.

---

## Overview

`pbkdf2.ts` exports a single class, `PBKDF2`, implementing the PBKDF2 key derivation
function (RFC 2898 §5.2). Given a password, salt, and iteration count, PBKDF2 derives
a key of arbitrary length by repeatedly applying a `KeyedHash` (typically HMAC-SHA256)
and XOR-accumulating the results.

**Why it is deprecated:** PBKDF2 is a purely computational KDF — its work factor scales
only with CPU time, not memory. Attackers with GPUs or ASICs can test billions of
passwords per second by parallelising the computation cheaply. Memory-hard KDFs (Argon2id,
scrypt) force each password guess to allocate a large memory buffer, making parallelism
far more expensive. For any new password hashing or key derivation from passwords, use
Argon2id or scrypt instead.

---

## Security Notes

**Minimum iteration count:** The source comment recommends at least 10,000 rounds. As
of 2024, NIST SP 800-132 recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256
for password storage. The default of 10,000 in this library is too low for modern
threat models. Pass an explicit `rounds` parameter with an appropriate value.

**Salt must be random and unique per password.** A salt of at least 16 bytes generated
by `Random.get(16)` should be used. Never reuse salts or use predictable values (e.g.
usernames, timestamps).

**`selftest()` uses only 2 rounds.** The self-test is not a security check; it verifies
the algorithm produces the correct RFC vector for `password`/`salt`/`c=2`.

**Output comparison:** When comparing derived keys, use `constantTimeEqual` to prevent
timing oracles, even though the test-vector comparison in `selftest()` uses a plain
string equality (acceptable there because it is a hardcoded, public test vector, not
an attacker-controlled input — this is documented in the source code comment).

---

## API Reference

### `class PBKDF2`

#### `constructor(hmac: KeyedHash, rounds?: number)`

**Parameters:**
- `hmac` — any `KeyedHash` implementation (typically `new HMAC(new SHA256())`)
- `rounds` — iteration count; defaults to 10,000

**Example:**
```typescript
import { PBKDF2, HMAC, SHA256 } from 'leviathan';

const pbkdf2 = new PBKDF2(new HMAC(new SHA256()), 600_000);
```

---

#### `hash(password: Uint8Array, salt: Uint8Array, length?: number): Uint8Array`

Derives a key from `password` and `salt`.

**Parameters:**
- `password` — password bytes (from `Convert.str2bin(passwordString)`)
- `salt` — random salt (at least 16 bytes); must be unique per password
- `length` — derived key length in bytes; defaults to `hmac.hashSize / 2` if omitted

**Returns:** `Uint8Array` of the requested `length`

**Example:**
```typescript
import { PBKDF2, HMAC, SHA256, Convert, Random } from 'leviathan';

const rng    = new Random();
const pbkdf2 = new PBKDF2(new HMAC(new SHA256()), 600_000);

const password = Convert.str2bin('correct horse battery staple');
const salt     = rng.get(16)!;  // store alongside the hash

const derivedKey = pbkdf2.hash(password, salt, 32);  // 256-bit derived key
```

---

#### `selftest(): boolean`

Verifies the implementation against the RFC 2898 test vector:
- password: `"password"`, salt: `"salt"`, c: 2, expected SHA-256 output:
  `ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43`

**Returns:** `true` if the implementation is correct

---

## Usage Examples

### Key derivation for encryption

```typescript
import { PBKDF2, HMAC, SHA256, Serpent_CBC_PKCS7, Convert, Random } from 'leviathan';

const rng    = new Random();
const pbkdf2 = new PBKDF2(new HMAC(new SHA256()), 600_000);

// Derive a 32-byte key and 16-byte IV from a passphrase
const password = Convert.str2bin('user passphrase');
const salt     = rng.get(32)!;  // persist the salt alongside the ciphertext

const material   = pbkdf2.hash(password, salt, 48);  // 32 key + 16 IV
const key        = material.subarray(0, 32);
const iv         = material.subarray(32, 48);

const cipher     = new Serpent_CBC_PKCS7();
const ciphertext = cipher.encrypt(key, Convert.str2bin('Secret data'), iv);

// To decrypt: re-derive key and IV from the same password and stored salt
```

---

## Error Conditions

- **`rounds = 0`:** The inner loop `for (let i = 1; i < 0; ...)` never executes. The
  outer `init()/update()/digest()` call still runs once (the PRF application for block
  1, iteration 1). This is technically 1 round of PBKDF2, not 0 — the loop body handles
  rounds 2 through N. Passing 0 is effectively 1 round.
- **`length` larger than `(2^32 − 1) × hashSize`:** RFC 2898 defines this as the maximum
  derived key length. In practice, JavaScript number limits will be hit before this.
- **Null/undefined inputs:** Will throw a runtime `TypeError`.

---

## See Also

- [hmac.ts](./hmac.md) — `HMAC` and `HMAC_SHA256` used as the PBKDF2 PRF
- [random.ts](./random.md) — CSPRNG for generating salts
- [index.ts](./index.md) — library overview and deprecation context
