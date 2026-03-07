```
  ██     ▐█████ ██     ▐█▌  ▄█▌   ███▌ ▀███████▀▄██▌  ▐█▌  ███▌    ██▌   ▓▓
 ▐█▌     ▐█▌    ▓█     ▐█▌  ▓██  ▐█▌██    ▐█▌   ███   ██▌ ▐█▌██    ▓██   ██
 ██▌     ░███   ▐█▌    ██   ▀▀   ██ ▐█▌   ██   ▐██▌   █▓  ▓█ ▐█▌  ▐███▌  █▓
 ██      ██     ▐█▌    █▓  ▐██  ▐█▌  █▓   ██   ▐██▄▄ ▐█▌ ▐█▌  ██  ▐█▌██ ▐█▌
▐█▌     ▐█▌      ██   ▐█▌  ██   ██   ██  ▐█▌   ██▀▀████▌ ██   ██  ██ ▐█▌▐█▌
▐▒▌     ▐▒▌      ▐▒▌  ██   ▒█   ██▀▀▀██▌ ▐▒▌   ▒█    █▓░ ▒█▀▀▀██▌ ▒█  ██▐█
█▓ ▄▄▓█ █▓ ▄▄▓█   ▓▓ ▐▓▌  ▐▓▌  ▐█▌   ▐▒▌ █▓   ▐▓▌   ▐▓█ ▐▓▌   ▐▒▌▐▓▌  ▐███
▓██▀▀   ▓██▀▀      ▓█▓█   ▐█▌  ▐█▌   ▐▓▌ ▓█   ▐█▌   ▐█▓ ▐█▌   ▐▓▌▐█▌   ██▓
                    ▓█                               ▀▀        ▐█▌▌▌
```
# Leviathan Documentation

## Module Reference

| Category | Module | Description |
|----------|--------|-------------|
| **Symmetric Ciphers** | [serpent.ts](./serpent.md) | Serpent-256 block cipher (128/192/256-bit keys), bitslice implementation |
| **Block Modes** | [blockmode.ts](./blockmode.md) | CBC and CTR mode wrappers |
| **Stream Ciphers** | [chacha20.ts](./chacha20.md) | ChaCha20 stream cipher (Bernstein; unauthenticated) |
| **AEAD** | [chacha20poly1305.ts](./chacha20poly1305.md) | XChaCha20-Poly1305 and ChaCha20-Poly1305 (RFC 8439) |
| **Hash Functions** | [sha256.ts](./sha256.md) | SHA-256 |
| | [sha512.ts](./sha512.md) | SHA-512 |
| | [sha3.ts](./sha3.md) | SHA-3 (256, 384, 512), Keccak (256, 384, 512), SHAKE128, SHAKE256 |
| **Padding** | [padding.ts](./padding.md) | PKCS#7 |
| **MAC** | [hmac.ts](./hmac.md) | HMAC (parameterised by hash); HMAC-SHA256, HMAC-SHA512 convenience classes |
| **Key Derivation** | [argon2id.ts](./argon2id.md) | Argon2id — memory-hard KDF (RFC 9106); recommended for all new code |
| | [pbkdf2.ts](./pbkdf2.md) | PBKDF2 — *deprecated, use Argon2id* |
| **Asymmetric / Key Exchange** | [x25519.ts](./x25519.md) | Curve25519 (ECDH) and Ed25519 (signatures) |
| **Utilities** | [base.ts](./base.md) | Format converters (hex, base64, string) and utilities (xor, compare, clear) |
| | [random.ts](./random.md) | Fortuna-based CSPRNG with entropy collection |
| **Deprecated** | [pbkdf2.ts](./pbkdf2.md) | Low memory-hardness KDF — use Argon2id for new code |
| | [uuid.ts](./uuid.md) | UUID generation — out of scope for a crypto library, may be removed |

## Supporting Documentation

| File | Description |
| ---- | ----------- |
| [Vector Corpus](./vector_corpus.md) | Testing Documentation and Vector corpus (~12,500) |
| [Testing Suite](./test_suite.md) | Current Testing Suite Status |
| [Serpent Audit](./serpent_audit.md) |  Serpent-256 Algorithm Audit |
| [SHA256 Audit](./sha256_audit.md) | SHA256 Algorithm Audit |
| [Serpent Reference](./serpent_reference.md) | Serpent-256 Reference Guide |
| [SHA256 Reference](./sha256_reference.md) | SHA256 Reference Guide |
| [Branding](./branding.md) | Project Brand Guide |

## Research

| File | Description |
| ---- | ----------- |
| [Biclique Toolchain](https://github.com/xero/BicliqueFinder/blob/main/biclique-toolchain.md) ‡ | BicliqueFinder is a semi-automated Java tool for discovering biclique structures in block ciphers. Covers build setup, formula bug discovery, and validation against published figures. |
| [Biclique Attack Research](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md) ‡ | BicliqueFinder was used to reproduce, validate, and optimize the best known biclique attack on full 32-round Serpent-256. |

> [!NOTE]
> ‡ External files hosted in our [BicliqueFinder](https://github.com/xero/BicliqueFinder) fork.

### Findings

#### Our research outperformed the published result via three independent optimizations
v position (−0.18 bits, eliminating C_falsepos), biclique nibble selection (−0.01 bits), and nabla key index K17 over K18 (−0.01 bits). a total improvement of **0.20 bits**, yielding **2^{255.19}** at **2^{4}** data complexity.

#### Key structural finding

The time-data tradeoff moving away from the ciphertext is never favorable. Each step (K31→K30→K29) trades ~2–4 bits of time complexity for 12–40 bits of data complexity. K31 is not just the best delta key index, it is the only viable one.

---

## Installation

```bash
bun i leviathan
# or
npm install leviathan
```

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
