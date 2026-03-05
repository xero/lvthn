# chacha20poly1305.ts (in blockmode.ts)

Authenticated encryption with associated data — ChaCha20-Poly1305 (96-bit nonce) and
XChaCha20-Poly1305 (192-bit nonce).

---

## Overview

`ChaCha20Poly1305` and `XChaCha20Poly1305` implement AEAD (Authenticated Encryption
with Associated Data) as specified in RFC 8439. They combine:

- **ChaCha20** (RFC 8439 §2.4) for stream encryption — identical security margin to the
  standalone ChaCha20, but using the IETF variant with a 32-bit counter and 96-bit nonce
- **Poly1305** (RFC 8439 §2.5) for authentication — a one-time polynomial MAC that
  produces a 16-byte tag over both the ciphertext and optional additional data

AEAD schemes solve a fundamental problem with stream ciphers and block cipher modes: they
encrypt *and* authenticate in a single operation. An attacker who modifies the ciphertext
cannot produce a valid tag, so decryption either succeeds with authentic data or throws
an error. There is no silent corruption.

**XChaCha20Poly1305 is recommended for general use.** Its 192-bit nonce is large enough
to generate randomly without collision risk (birthday bound at 2^96 messages per key,
compared to 2^48 for the 96-bit nonce variant). `ChaCha20Poly1305` requires careful
nonce management — use it only when you manage nonces as counters or derive them
deterministically.

Both classes are exported from `blockmode.ts` and re-exported from `Wiki Home`:
```typescript
import { ChaCha20Poly1305, XChaCha20Poly1305 } from 'leviathan';
```

---

## Security Notes

**Nonce must be unique per (key, message).** Both classes are stream-cipher-based: if the
same (key, nonce) pair encrypts two different messages, the keystreams cancel in XOR,
directly exposing the XOR of the two plaintexts. This is catastrophic.

- For `XChaCha20Poly1305`: generate a fresh 24-byte nonce with `Random.get(24)` for every
  message. At 192 bits, random nonce collisions are negligible in practice.
- For `ChaCha20Poly1305`: use a 96-bit counter or derive nonces deterministically (e.g.
  message sequence numbers serialised to 12 bytes). Do not generate randomly — the birthday
  bound at 2^48 messages per key is reachable for high-volume senders.

**Verify before decrypt.** `decrypt()` computes the Poly1305 tag over the *received*
ciphertext before decrypting a single byte. If the tag does not match, an exception is
thrown immediately and no plaintext is returned. This is the correct AEAD discipline;
decrypting and then checking the tag (or not checking at all) exposes the caller to
chosen-ciphertext attacks.

**Tag comparison is constant-time.** `decrypt()` uses `constantTimeEqual` for tag
comparison. Never compare tags with `===`, `Buffer.equals()`, or a byte loop with
an early exit — timing oracles can allow tag forgery one byte at a time.

**AAD is authenticated but not encrypted.** Additional authenticated data (the optional
`aad` parameter) is included in the Poly1305 MAC computation but is not part of the
ciphertext. Transmit it alongside the ciphertext and tag as plaintext. If AAD is omitted,
an empty byte array is used.

**Poly1305 key is one-time.** A fresh 32-byte Poly1305 key is derived from ChaCha20 at
counter=0 for every (key, nonce) pair. It is never reused. The Poly1305 key is derived
internally and not exposed to callers.

**Key must not be reused across protocols.** Use a separate key for
ChaCha20-Poly1305 encryption versus any other use (e.g. HMAC). Derive per-purpose keys
from a master key using Argon2id or HKDF.

**IETF ChaCha20, not Bernstein ChaCha20.** These classes use the RFC 8439 (IETF) variant
of ChaCha20 with a 32-bit counter and 96-bit nonce. This is **not interoperable** with
the `ChaCha20` class in `chacha20.ts`, which uses the original Bernstein format with a
64-bit nonce and 64-bit counter.

---

## API Reference

### `class ChaCha20Poly1305`

AEAD using ChaCha20-Poly1305 per RFC 8439. Uses a 96-bit (12-byte) nonce.

**When to use:** When nonces are counters or deterministically derived, and nonce
management is tightly controlled. Not recommended for random nonces.

#### `encrypt(key, nonce, plaintext, aad?): { ciphertext, tag }`

Encrypts and authenticates `plaintext`.

**Parameters:**
- `key` — 32-byte (256-bit) key
- `nonce` — 12-byte (96-bit) nonce; must be unique per (key, message)
- `plaintext` — message bytes (any length, including empty)
- `aad` — additional authenticated data (optional; authenticated but not encrypted)

**Returns:** `{ ciphertext: Uint8Array, tag: Uint8Array }`
- `ciphertext.length === plaintext.length`
- `tag` is always 16 bytes

**Throws:** `'ChaCha20Poly1305: key must be 32 bytes'` | `'ChaCha20Poly1305: nonce must be 12 bytes'`

---

#### `decrypt(key, nonce, ciphertext, tag, aad?): Uint8Array`

Verifies the tag and decrypts `ciphertext`. **Always verifies before decrypting.**

**Parameters:**
- `key` — 32-byte key (must match encryption key)
- `nonce` — 12-byte nonce (must match encryption nonce)
- `ciphertext` — encrypted bytes
- `tag` — 16-byte Poly1305 tag from `encrypt()`
- `aad` — additional authenticated data (must match what was passed to `encrypt()`)

**Returns:** `Uint8Array` plaintext

**Throws:**
- `'ChaCha20Poly1305: key must be 32 bytes'`
- `'ChaCha20Poly1305: nonce must be 12 bytes'`
- `'ChaCha20Poly1305: tag must be 16 bytes'`
- `'ChaCha20Poly1305: authentication failed'` — tag mismatch; ciphertext or tag was tampered

---

### `class XChaCha20Poly1305`

AEAD using XChaCha20-Poly1305 (XChaCha20 IETF draft, draft-irtf-cfrg-xchacha). Uses a
192-bit (24-byte) nonce derived via HChaCha20. **Recommended for most use cases.**

The extended nonce works by running HChaCha20 over the first 16 bytes of the 24-byte
nonce to derive a 256-bit subkey, then delegating to ChaCha20-Poly1305 with the subkey
and the remaining 8 nonce bytes. This eliminates the nonce management complexity of the
96-bit variant.

#### `encrypt(key, nonce, plaintext, aad?): { ciphertext, tag }`

**Parameters:**
- `key` — 32-byte key
- `nonce` — 24-byte nonce; safe to generate randomly with `Random.get(24)`
- `plaintext` — message bytes
- `aad` — additional authenticated data (optional)

**Returns:** `{ ciphertext: Uint8Array, tag: Uint8Array }`

**Throws:** `'XChaCha20Poly1305: key must be 32 bytes'` | `'XChaCha20Poly1305: nonce must be 24 bytes'`

---

#### `decrypt(key, nonce, ciphertext, tag, aad?): Uint8Array`

**Parameters:** same structure as `ChaCha20Poly1305.decrypt()`, but `nonce` is 24 bytes.

**Returns:** `Uint8Array` plaintext

**Throws:**
- `'XChaCha20Poly1305: key must be 32 bytes'`
- `'XChaCha20Poly1305: nonce must be 24 bytes'`
- `'XChaCha20Poly1305: tag must be 16 bytes'`
- `'XChaCha20Poly1305: authentication failed'`

---

## Usage Examples

### XChaCha20-Poly1305 with random nonce (recommended)

```typescript
import { XChaCha20Poly1305, Random } from 'leviathan';

const rng    = new Random();
const aead   = new XChaCha20Poly1305();

const key   = rng.get(32)!;  // 256-bit key — store securely, never transmit
const nonce = rng.get(24)!;  // fresh random 192-bit nonce per message

const plaintext = new TextEncoder().encode('Hello, authenticated world!');
const aad       = new TextEncoder().encode('message-id:42');  // optional context

// Encrypt
const { ciphertext, tag } = aead.encrypt(key, nonce, plaintext, aad);

// Transmit: nonce || tag || ciphertext (and aad if not implicit in context)

// Decrypt (on the receiving end)
const recovered = aead.decrypt(key, nonce, ciphertext, tag, aad);
console.log(new TextDecoder().decode(recovered));  // "Hello, authenticated world!"
```

---

### ChaCha20-Poly1305 with counter nonce

```typescript
import { ChaCha20Poly1305 } from 'leviathan';

const aead = new ChaCha20Poly1305();

// Derive a 256-bit key (use Argon2id for passphrase → key)
const key: Uint8Array = /* 32 bytes from Argon2id.deriveKey() */;

// Counter-based nonce: 4-byte sender ID + 8-byte message counter
function makeNonce(senderId: number, msgCounter: bigint): Uint8Array {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(0, senderId, false);     // big-endian sender ID
  new DataView(nonce.buffer).setBigUint64(4, msgCounter, false); // big-endian counter
  return nonce;
}

const nonce = makeNonce(0x00000001, 1n);

const { ciphertext, tag } = aead.encrypt(key, nonce, plaintext);
```

---

### Tamper detection

```typescript
import { XChaCha20Poly1305, Random } from 'leviathan';

const rng  = new Random();
const aead = new XChaCha20Poly1305();
const key  = rng.get(32)!;
const nonce = rng.get(24)!;

const { ciphertext, tag } = aead.encrypt(key, nonce,
  new TextEncoder().encode('transfer $100'));

// Attacker flips a bit in the ciphertext
const tampered = ciphertext.slice();
tampered[0] ^= 0x01;

try {
  aead.decrypt(key, nonce, tampered, tag);
} catch (e) {
  console.log(e.message);  // "XChaCha20Poly1305: authentication failed"
}
```

---

### Passphrase → key → AEAD (full workflow)

```typescript
import { Argon2id, ARGON2ID_DERIVE, XChaCha20Poly1305, Random } from 'leviathan';

const rng    = new Random();
const argon  = new Argon2id();
const aead   = new XChaCha20Poly1305();

// Derive a key from a passphrase
const { key, salt } = await argon.deriveKey('my passphrase');

// Encrypt
const nonce = rng.get(24)!;
const { ciphertext, tag } = aead.encrypt(
  key,
  nonce,
  new TextEncoder().encode('secret message'),
);

// Store: salt (32 bytes) + nonce (24 bytes) + tag (16 bytes) + ciphertext
// On decrypt, rederive the key with the stored salt and ARGON2ID_DERIVE params
```

---

## What to Transmit / Store

To allow decryption at a later time or on another system, transmit or store the
following alongside the ciphertext:

| Field | Size | Notes |
|-------|------|-------|
| `nonce` | 12 or 24 bytes | Required; unique per message |
| `tag` | 16 bytes | Required; authenticate before decrypt |
| `ciphertext` | same as plaintext | Required |
| `aad` | variable | Required if non-empty — must match exactly |

The `key` is **never** transmitted. Derive or exchange it out-of-band (Argon2id for
passphrases, Curve25519 for key exchange).

---

## Error Conditions

| Error message | Cause |
|---------------|-------|
| `ChaCha20Poly1305: key must be 32 bytes` | Key is not exactly 32 bytes |
| `ChaCha20Poly1305: nonce must be 12 bytes` | Nonce is not exactly 12 bytes |
| `ChaCha20Poly1305: tag must be 16 bytes` | Tag passed to decrypt is not 16 bytes |
| `ChaCha20Poly1305: authentication failed` | Tag mismatch — ciphertext, tag, nonce, key, or AAD was wrong or tampered |
| `XChaCha20Poly1305: key must be 32 bytes` | Key is not exactly 32 bytes |
| `XChaCha20Poly1305: nonce must be 24 bytes` | Nonce is not exactly 24 bytes |
| `XChaCha20Poly1305: tag must be 16 bytes` | Tag passed to decrypt is not 16 bytes |
| `XChaCha20Poly1305: authentication failed` | Tag mismatch |

---

## See Also

- [blockmode.ts](./blockmode.md) — CBC and CTR mode wrappers (also the source file for these AEAD classes)
- [chacha20.ts](./chacha20.md) — unauthenticated Bernstein ChaCha20 (not RFC 8439)
- [hmac.ts](./hmac.md) — HMAC for Encrypt-then-MAC if AEAD is not available
- [argon2id.ts](./argon2id.md) — passphrase → key derivation
- [x25519.ts](./x25519.md) — Curve25519 ECDH for key exchange
- [random.ts](./random.md) — CSPRNG for key and nonce generation
- [Wiki Home](./README.md) — library overview
