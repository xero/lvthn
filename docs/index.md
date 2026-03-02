# leviathan

A clean, lightweight TypeScript cryptographic library providing symmetric ciphers,
stream ciphers, hash functions, MACs, key derivation, and asymmetric key exchange —
optimised for correctness, security, and minimal dependencies.

---

## Installation

```bash
npm install leviathan
```

---

## Quick Start

A complete encrypt/decrypt cycle using Serpent-256 in CBC mode with PKCS7 padding:

```typescript
import { Serpent_CBC_PKCS7, Random, Convert } from 'leviathan';

const rng    = new Random();
const cipher = new Serpent_CBC_PKCS7();

// Generate a 256-bit key and a 128-bit IV
const key = rng.get(32)!;   // 32 bytes = 256 bits
const iv  = rng.get(16)!;   // 16 bytes = one block

const plaintext  = Convert.str2bin('Hello, leviathan!');
const ciphertext = cipher.encrypt(key, plaintext, iv);
const recovered  = cipher.decrypt(key, ciphertext, iv);

console.log(Convert.bin2str(recovered)); // "Hello, leviathan!"
```

---

## Module Reference

| Category | Module | Description |
|----------|--------|-------------|
| **Symmetric Ciphers** | [serpent.ts](./serpent.md) | Serpent-256 block cipher (128/192/256-bit keys), bitslice implementation |
| **Stream Ciphers** | [chacha20.ts](./chacha20.md) | ChaCha20 stream cipher (Bernstein; unauthenticated) |
| **AEAD** | [chacha20poly1305.ts](./chacha20poly1305.md) | XChaCha20-Poly1305 and ChaCha20-Poly1305 (RFC 8439) |
| **Block Modes** | [blockmode.ts](./blockmode.md) | CBC and CTR mode wrappers; ECB removed |
| **Hash Functions** | [sha256.ts](./sha256.md) | SHA-256 |
| | [sha512.ts](./sha512.md) | SHA-512 |
| | [sha3.ts](./sha3.md) | SHA-3 (256, 384, 512), Keccak (256, 384, 512), SHAKE128, SHAKE256 |
| **MAC** | [hmac.ts](./hmac.md) | HMAC (parameterised by hash); HMAC-SHA256, HMAC-SHA512 convenience classes |
| **Key Derivation** | [argon2id.ts](./argon2id.md) | Argon2id — memory-hard KDF (RFC 9106); recommended for all new code |
| | [pbkdf2.ts](./pbkdf2.md) | PBKDF2 — *deprecated, use Argon2id* |
| **Asymmetric / Key Exchange** | [x25519.ts](./x25519.md) | Curve25519 (ECDH) and Ed25519 (signatures) |
| **Utilities** | [base.ts](./base.md) | Format converters (hex, base64, string) and utilities (xor, compare, clear) |
| | [random.ts](./random.md) | Fortuna-based CSPRNG with entropy collection |
| **Deprecated** | [pbkdf2.ts](./pbkdf2.md) | Low memory-hardness KDF — use Argon2id for new code |
| | [uuid.ts](./uuid.md) | UUID generation — out of scope for a crypto library, may be removed |

---

## Security Philosophy

leviathan prioritises security margin over speed. The primary symmetric cipher,
Serpent, was the most conservative AES finalist — it has a 32-round structure
versus AES's 10/12/14, giving an estimated security margin that remains
unbroken. Broken or weak primitives have been removed entirely: SHA-1, the ECB
block mode, PKCS5 and zero padding schemes, and the original AES/Rijndael cipher
are all absent from this library. Security-sensitive byte comparisons — signature
verification and MAC tag checking — use `constantTimeEqual`, an XOR-accumulate
function that always visits every byte regardless of content, preventing
timing-oracle attacks such as byte-at-a-time HMAC forgery. The Serpent S-boxes
are implemented as Boolean gate circuits (bitslice form) with no table lookups
and no data-dependent branches, eliminating the main practical side-channel
attack vector in pure JavaScript. JavaScript engines provide no formal
constant-time guarantees; for formally proven constant-time requirements a
WebAssembly or native implementation is necessary.

---

## See Also

- [AUDIT.md](../AUDIT.md) — full cryptographic audit report
- [TEST_REPORT.md](../TEST_REPORT.md) — test vector provenance and results
- [SERPENT_REFERENCE.md](../SERPENT_REFERENCE.md) — deep technical reference for the Serpent algorithm
