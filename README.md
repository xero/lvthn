<img src="https://github.com/xero/lvthn/raw/main/docs/logo.svg" alt="Leviathan logo" width="400">

# leviathan — Serpent-256 cryptography for the web

A TypeScript cryptographic library built around **Serpent-256** — the AES
finalist that received more first-place security votes than Rijndael from
the NIST evaluation committee, and was designed with a larger security
margin by construction: 32 rounds versus AES's 10/12/14.

For applications where throughput is not the primary constraint — file
encryption, key derivation, secure storage — Serpent-256 is the stronger
choice. leviathan makes it practical for web and server-side TypeScript.

## Why Serpent-256

AES (Rijndael) won the competition on performance. Serpent won on security
margin. The NIST evaluation committee's own analysis gave Serpent more
first-place security votes — Rijndael was selected because speed mattered
for the hardware and embedded targets NIST was optimising for in 2001.

For software running on modern hardware where milliseconds of encryption
latency are acceptable, that tradeoff no longer applies.

**Security margin.** Serpent has been a target of cryptanalytic research
since the AES competition. The current state of the art:

- **Best known reduced-round attack:** multidimensional linear cryptanalysis
  reaching 12 of 32 rounds (Nguyen, Wu & Wang, ACISP 2011) — less than
  half the full cipher, requiring 2¹¹⁸ known plaintexts and 2²²⁸·⁸ time.
- **Best known full-round attack:** biclique cryptanalysis of full 32-round
  Serpent-256 (de Carvalho & Kowada, SBSeg 2020), time complexity 2²⁵⁵·²¹ —
  only 0.79 bits below the 256-bit brute-force ceiling of 2²⁵⁶, and requires
  2⁸⁸ chosen ciphertexts, making it strictly less practical than brute force.
  For comparison, the analogous biclique attack on full-round AES-256
  (Bogdanov et al., 2011) reaches 2²⁵⁴·⁴ — Serpent-256 is marginally harder
  to attack by this method than AES-256.

The attack papers are included in the repository. See
[`docs/AUDIT.md`](docs/AUDIT.md) for the full analysis.

**Implementation.** Serpent's S-boxes are implemented as Boolean gate
circuits — no table lookups, no data-dependent memory access, no
data-dependent branches. Every bit is processed unconditionally on every
block. This is the most timing-safe cipher implementation approach
available in a JavaScript runtime, where JIT optimisation can otherwise
introduce observable timing variation.

**Key size.** 256-bit keys only in the default API — no 128 or 192-bit
variants, no key-size downgrade risk.

## Correctness and verification

Every primitive is verified against authoritative external vectors before
inclusion. The test suite runs **[N] tests** across the following corpora:

| Source | Vectors | Primitives |
|--------|---------|-----------|
| AES submission floppy4 — KAT, S-box entry, intermediate values | 2,496 | Serpent ECB |
| AES submission floppy4 — Monte Carlo ECB + CBC | 1,200 × 10,000 | Serpent block function |
| NESSIE — Serpent-256-128 + Serpent-128-128 | 2,312 | Serpent ECB, all key sizes |
| RFC 8439 Appendix A | ~10 | ChaCha20-Poly1305 AEAD |
| IETF draft-irtf-cfrg-xchacha | ~3 | XChaCha20-Poly1305 |
| RFC 4231 TC1/TC2/TC6 | 3 | HMAC-SHA-256 |
| RFC 4868 | 6 | HMAC-SHA-256/512 |
| NIST FIPS 180-4 §B.1 | 4 | SHA-256 |
| NIST FIPS 202 CAVP | 1,024 | SHA-3, SHAKE |

The S-box entry vectors (`ecb_tbl.txt`) specifically target individual
S-box inputs to catch Boolean circuit errors that variable-text and
variable-key KAT vectors would miss. The Monte Carlo suites run
~19.2 million encrypt/decrypt operations with a chained key-update loop —
a single wrong bit compounds to a completely wrong output within the first
few iterations.

Vector provenance, verification methodology, and audit history for every
corpus are documented in [`docs/TESTING.md`](docs/TESTING.md).

## Security audit

The implementation was audited against the published cryptanalytic
literature for each primitive. The audit covers known attack classes,
the gap between full-round and best-known-attack rounds, and a risk
assessment for each algorithm.

The Serpent implementation was verified correct against the official AES
submission reference C implementation (floppy1) and all AES submission
test vector classes: KAT, S-box entry, intermediate round values, and
ECB/CBC Monte Carlo. The SHA-256 implementation was independently
confirmed correct against FIPS 180-4 and RFC 4231 — implementation
and test vectors both verified from primary sources.

Full audit trail in [docs/AUDIT.md](docs/AUDIT.md) and
[docs/SHA256_AUDIT.md](docs/SHA256_AUDIT.md).

## Design decisions

- **TypeScript-first** — typed arrays (`Uint8Array`) throughout, no
  string-based crypto APIs, no implicit encoding assumptions. Transpiles
  cleanly to JavaScript; the type system enforces correct usage at the
  call site.
- **Security-first removals** — SHA-1, AES/Rijndael, ECB mode, PKCS5
  padding, and HMAC-SHA1 are not present. Broken or semantically unsafe
  primitives are absent, not just undocumented.
- **Constant-time operations** — all security-sensitive comparisons use
  `constantTimeEqual` (XOR-accumulate, no early exit). The Fortuna PRNG
  block cipher is Serpent rather than AES, consistent throughout.
- **Minimal dependencies** — zero runtime dependencies. Argon2id uses a
  single WASM package; everything else is pure TypeScript.

## Supported algorithms

**Symmetric encryption**
- Serpent-256 — 128-bit block, 256-bit keys, 32-round bitslice
- ChaCha20 — stream cipher (unauthenticated)
- ChaCha20-Poly1305 — AEAD (RFC 8439, 96-bit nonce)
- XChaCha20-Poly1305 — AEAD (192-bit nonce; recommended for random nonces)

**Block modes**
- CTR, CBC (ECB absent, only used in Monte Carlo validations)
- PKCS7 padding (PKCS5 and zero padding, absent by design)

**Hashing**
- SHA-256, SHA-512
- SHA-3 (256/384/512), Keccak (256/384/512), SHAKE128/256

**MACs and key derivation**
- HMAC — parameterised; `HMAC_SHA256`, `HMAC_SHA512` convenience classes
- Argon2id — recommended for password hashing and key derivation
- PBKDF2 *(deprecated — migrate to Argon2id)*

**Asymmetric**
- Curve25519 (ECDH key exchange)
- Ed25519 (signatures)

**Utilities**
- Fortuna CSPRNG (Serpent-256 block cipher)
- `constantTimeEqual`, xor, concat, clear
- Format converters: hex, base64, base64url, UTF-8, binary
- UUID *(deprecated — use `crypto.randomUUID()`)*


## Quick start

```typescript
import { Serpent_CBC_PKCS7, Random, Convert } from 'leviathan';

const rng    = new Random();
const cipher = new Serpent_CBC_PKCS7();

const key  = rng.get(32)!;   // 256-bit key
const iv   = rng.get(16)!;   // fresh random IV per message

const plaintext  = Convert.str2bin('Hello, leviathan!');
const ciphertext = cipher.encrypt(key, plaintext, iv);
const recovered  = cipher.decrypt(key, ciphertext, iv);

console.log(Convert.bin2str(recovered)); // "Hello, leviathan!"
```

## Documentation

**Full API documentation:** in [./docs/](./docs/README.md) or [the wiki](https://github.com/xero/lvthn/wiki)

| Module | Description |
|--------|-------------|
| [serpent.ts](https://github.com/xero/lvthn/wiki/serpent) | Serpent-256 block cipher |
| [chacha20.ts](https://github.com/xero/lvthn/wiki/chacha20) | ChaCha20 stream cipher |
| [chacha20poly1305.ts](https://github.com/xero/lvthn/wiki/chacha20poly1305) | ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD |
| [blockmode.ts](https://github.com/xero/lvthn/wiki/blockmode) | CBC, CTR mode wrappers |
| [sha256.ts](https://github.com/xero/lvthn/wiki/sha256) | SHA-256 |
| [sha512.ts](https://github.com/xero/lvthn/wiki/sha512) | SHA-512 |
| [sha3.ts](https://github.com/xero/lvthn/wiki/sha3) | SHA-3, Keccak, SHAKE |
| [hmac.ts](https://github.com/xero/lvthn/wiki/hmac) | HMAC |
| [pbkdf2.ts](https://github.com/xero/lvthn/wiki/pbkdf2) | PBKDF2 *(deprecated)* |
| [x25519.ts](https://github.com/xero/lvthn/wiki/x25519) | Curve25519 ECDH and Ed25519 signatures |
| [base.ts](https://github.com/xero/lvthn/wiki/base) | Format converters and utilities |
| [random.ts](https://github.com/xero/lvthn/wiki/random) | Fortuna CSPRNG |
| [padding.ts](https://github.com/xero/lvthn/wiki/padding) | PKCS7 padding |
| [uuid.ts](https://github.com/xero/lvthn/wiki/uuid) | UUID *(deprecated)* |

**SLDC documentation:**

| Document | Description |
| -------- | ----------- |
| [Vector Corpus](https://github.com/xero/lvthn/wiki/vector_corpus) | Testing Documentation and Vector corpus (~12,500) |
| [Testing Suite](https://github.com/xero/lvthn/wiki/test_suite) | Current Testing Suite Status |

## Test suite

leviathan uses Vitest. To run all tests:

```bash
# with bun
bun run test
# with npm
npm run test
```

See [docs/TESTING.md](docs/TESTING.md) for more details.


## Contributing

1. Create an issue and describe your idea
2. [Fork it](https://github.com/xero/leviathan/fork)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Publish the branch (`git push origin my-new-feature`)
6. Create a new pull request


## Security Notices

**Constant-time comparisons**: All security-sensitive byte comparisons (signature
verification, MAC tag checking) use `constantTimeEqual`, an XOR-accumulate function
that visits every byte regardless of content. This prevents timing-oracle attacks such
as byte-at-a-time HMAC forgery. `constantTimeEqual` is also exported for use by
callers that need to compare keys, tags, or other secret values.

**Bitslice Serpent**: The Serpent cipher is implemented in bitslice form — S-boxes are
Boolean gate circuits with no table lookups and no data-dependent branches. This is the
most timing-safe Serpent implementation approach available in JavaScript.

**Absent primitives**: SHA-1, AES-Rijndael, ECB block mode, PKCS5, and zero padding
are absent from this library by design. (See: [Cryptographic Audit](./AUDIT.md))

**JIT caveat**: JavaScript engines provide no formal constant-time guarantees for
arbitrary code. The mitigations above eliminate the most practical attack vectors;
for applications requiring formally proven constant-time (e.g. side-channel-hardened
hardware wallets), a WebAssembly or native implementation is necessary see [leviathan-wasm](#).


## License
leviathan is written under the [MIT license](http://www.opensource.org/licenses/MIT).

```
  ██     ▐█████ ██     ▐█▌  ▄█▌   ███▌ ▀███████▀▄██▌  ▐█▌  ███▌    ██▌   ▓▓
 ▐█▌     ▐█▌    ▓█     ▐█▌  ▓██  ▐█▌██    ▐█▌   ███   ██▌ ▐█▌██    ▓██   ██
 ██▌     ░███   ▐█▌    ██   ▀▀   ██ ▐█▌   ██   ▐██▌   █▓  ▓█ ▐█▌  ▐███▌  █▓
 ██      ██     ▐█▌    █▓  ▐██  ▐█▌  █▓   ██   ▐██▄▄ ▐█▌ ▐█▌  ██  ▐█▌██ ▐█▌
▐█▌     ▐█▌      ██   ▐█▌  ██   ██   ██  ▐█▌   ██▀▀████▌ ██   ██  ██ ▐█▌▐█▌
▐▒▌     ▐▒▌      ▐▒▌  ██   ▒█   ██▀▀▀██▌ ▐▒▌   ▒█    █▓░ ▒█▀▀▀██▌ ▒█  ██▐█
█▓ ▄▄▓█ █▓ ▄▄▓█   ▓▓ ▐▓▌  ▐▓▌  ▐█▌   ▐▒▌ █▓   ▐▓▌   ▐▓█ ▐▓▌   ▐▒▌▐▓▌  ▐███
▓██▀▀   ▓██▀▀      ▓█▓█   ▐█▌  ▐█▌   ▐▓▌ ▓█   ▐█▌   ▐█▓ ▐█▌   ▐▓▌▐█▌   ██▓
                    ▓█         ▄▄▄▄▄▄▄▄▄▄            ▀▀        ▐█▌▌▌
                        ▄████████████████████▄▄
                     ▄██████████████████████ ▀████▄
                   ▄█████████▀▀▀     ▀███████▄▄███████▌
                  ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
                  ████████      ███▀▀     ████▀  █▀ █▀
                  ███████▌    ▀██▀         ██
                   ███████   ▀███           ▀██ ▀█▄
                    ▀██████   ▄▄██            ▀▀  ██▄
                      ▀█████▄   ▄██▄             ▄▀▄▀
                         ▀████▄   ▄██▄
                           ▐████   ▐███
                    ▄▄██████████    ▐███         ▄▄
                 ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
               ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███
                ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀
               ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄
               █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄███▀
               ▀██████▀             ▀████▄▄▄████▀
                                       ▀█████▀
                Serpent256 Cryptography for the Web
```
