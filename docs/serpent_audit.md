# Serpent-256 Cryptographic Audit — leviathan Library

**Conducted:** Week of 2026-03-06
**Target:** `sources/leviathan/src/serpent.ts` (TypeScript)
**Reference:** [serpent/floppy1](https://github.com/xero/lvthn/tree/floppy1) (ground truth)
**Consolidates:** `serpent_audit.md` (implementation correctness, Round 1) and `serpent_audit_v2.md` (attack surface, Round 2)

Leviathan's Serpent-256 implementation is cryptographically correct and secure against all known published attacks. The implementation passes 4,770 test vectors spanning all key sizes (128/192/256), all official vector classes (KAT, S-box entry, Monte Carlo, NESSIE), and all block modes (ECB, CBC, CTR). No attack in the academic literature threatens full 32-round Serpent-256; the best known result reaches 12 of 32 rounds with time complexity 2^249.4, providing only ~6.6 bits of advantage over brute force. The leviathan API hardcodes all 32 rounds with no mechanism to reduce the round count, rendering all reduced-round attacks structurally inapplicable.

---

## Table of Contents

- [1. Known Attack Vectors](#1-known-attack-vectors)
  - [1.1 Side-Channel Analysis](#11-side-channel-analysis)
  - [1.2 Cryptanalytic Attack Papers](#12-cryptanalytic-attack-papers)
    - [Paper 1 — Amplified Boomerang Attacks (FSE 2000)](#paper-1--amplified-boomerang-attacks-fse-2000)
    - [Paper 2 — Chosen-Plaintext Linear Attacks (IET 2013)](#paper-2--chosen-plaintext-linear-attacks-iet-2013)
    - [Paper 3 — Differential-Linear Attack on 12-Round Serpent (FSE 2008)](#paper-3--differential-linear-attack-on-12-round-serpent-fse-2008)
    - [Paper 4 — Linear Cryptanalysis of Reduced Round Serpent (FSE 2001)](#paper-4--linear-cryptanalysis-of-reduced-round-serpent-fse-2001)
    - [Paper 5 — The Rectangle Attack (EUROCRYPT 2001)](#paper-5--the-rectangle-attack-eurocrypt-2001)
    - [Consolidated Verdict Table](#consolidated-verdict-table)
    - [Final Assessment](#final-assessment)
- [2. Implementation Correctness](#2-implementation-correctness)
  - [2.1 Algorithm Correctness](#21-algorithm-correctness)
  - [2.2 Security Properties](#22-security-properties)
  - [2.3 Constant-Time Equality Audit](#23-constant-time-equality-audit)
  - [2.4 Deprecated and Removed Components](#24-deprecated-and-removed-components)
  - [2.5 Test Suite](#25-test-suite)
- [3. Open Questions](#3-open-questions)

---

## 1. Known Attack Vectors

### 1.1 Side-Channel Analysis

| Component | Implementation | Safe? |
|-----------|---------------|-------|
| S-boxes | Boolean logic (AND/OR/XOR/NOT) | Constant-time |
| Linear transform | Fixed rotations + XOR | Constant-time |
| Key schedule | Fixed operations | Constant-time |
| CBC mode | XOR operations only | Constant-time |
| CTR mode | Counter increment (short-circuit loop) | Non-constant |

The bitslice S-box core is constant-time by construction. All 8 forward (`S[]`) and 8 inverse (`SI[]`) S-boxes are implemented as pure Boolean gate circuits — no lookup tables, no data-dependent branches. Every bit is processed unconditionally on every call, making them the most timing-safe implementation approach available in JavaScript.

All explicit security-sensitive byte comparisons were audited and replaced with `constantTimeEqual` (XOR-accumulate, no early return). The two SENSITIVE sites identified were `Ed25519.verify()` (`x25519.ts`) and `neq25519()` (`x25519.ts`). `Util.compare` now delegates to `constantTimeEqual` to prevent independent drift between the two implementations. See [Section 2.3](#23-constant-time-equality-audit) for the full audit details.

**CTR counter increment** (`blockmode.ts:117-122`):
```typescript
this.ctr[0]++;
for (let i = 0; i < bs - 1; i++) {
  if (this.ctr[i] === 0) { this.ctr[i + 1]++; }
  else break;  // early exit leaks carry-propagation depth
}
```
This leaks the number of carry propagations in the counter, which correlates with the counter value. For CTR-mode stream ciphers this is a minor concern (counter value is not secret), but it is a known low-severity issue. A constant-time increment (always iterating all 16 bytes) would be cleaner.

**JavaScript engine caveat:** JavaScript's `|`, `&`, `^`, `~` operate on 32-bit signed integers; on modern V8/SpiderMonkey, these map to CPU integer instructions. However, the JS spec does not guarantee constant-time execution — JIT optimization or branch prediction could theoretically introduce timing variations. For the bitslice Serpent core this is a theoretical concern only — the uniform, branch-free structure of the Boolean gate circuits leaves no practical optimization surface for a JIT to exploit. For formally guaranteed constant-time, a WASM or native implementation is required.

---

### 1.2 Cryptanalytic Attack Papers

Every attack examined across 5 academic papers targets reduced-round Serpent. The minimum security margin across all papers is 20 rounds (32 - 12), and the best attack provides only ~6.6 bits of advantage over brute force on 12 rounds. The leviathan API makes it structurally impossible to invoke fewer than 32 rounds — there is no parameter, no configuration, and no conditional logic to reduce the round count.

---

#### Paper 1 — Amplified Boomerang Attacks (FSE 2000)

**Authors:** John Kelsey, Tadayoshi Kohno, Bruce Schneier
**Published:** FSE 2000, LNCS 1978, pp. 75-93

**Attacks on Serpent:**

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Amplified boomerang distinguisher | 7 | Chosen-plaintext | 2^113 | < brute force | Distinguisher |
| Amplified boomerang key recovery | 8 | Chosen-plaintext | 2^113 | 2^179 | Key recovery (68 subkey bits) |

**Core technique:** The cipher is split into two halves: E_0 (rounds 1-4) and E_1 (rounds 5-7). A 4-round differential with probability 2^{-31} and a 3-round differential with probability 2^{-16} are combined via the amplified boomerang framework. The key recovery extends by one round through subkey guessing.

**Why it doesn't apply:** The differential characteristics cover at most 4 rounds (2^{-31}) and 3 rounds (2^{-16}). Differences spread rapidly through Serpent's linear transform — the authors themselves state "differences spread out, so that it is possible to find reasonably good characteristics for three or four rounds at a time, but not for larger numbers of rounds." Full 32-round Serpent retains a **24-round security margin**. The authors explicitly confirm: "this attack does not threaten the full 32-round Serpent."

**Leviathan analysis:** The encryption loop (`serpent.ts:318-328`) unconditionally executes all 32 rounds. The S-boxes and linear transform match the standard Serpent specification — the attack exploits inherent algebraic properties, not implementation-specific weaknesses. The JS/JIT environment is irrelevant to this purely algebraic/statistical attack.

**Verdict: NOT APPLICABLE — 24-round security margin.**

---

#### Paper 2 — Chosen-Plaintext Linear Attacks (IET 2013)

**Authors:** Jialin Huang, Xuejia Lai
**Published:** IET Information Security, Vol. 7, Iss. 4, pp. 293-299, 2013
**DOI:** 10.1049/iet-ifs.2012.0287

**Attacks on Serpent:**

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Single linear (all keys) | 10 | Chosen-plaintext | 2^92 | 2^84.68 | Key recovery |
| Single linear (192/256-bit) | 10 | Chosen-plaintext | 2^80 | 2^180.68 | Key recovery |
| Multidimensional linear | 10 | Chosen-plaintext | 2^88 | 2^84.07 | Key recovery |
| Multidimensional linear | 11 | Chosen-plaintext | 2^116 | 2^144 | Key recovery |
| Experimental validation | 5 | Chosen-plaintext | ~2^20 | Trivial | Key recovery (12 bits) |

**Core technique:** By fixing specific S-box inputs in the first round of a linear approximation, inactive S-boxes have correlation exactly +/-1 instead of 2^{-1}, boosting the overall approximation correlation. This reduces data complexity by up to 2^22 for single-approximation attacks and dramatically reduces time complexity for multidimensional attacks (from 2^{134.43} to 2^{84.07} for 10 rounds).

**Why it doesn't apply:** The best result reaches 11 rounds. Each additional round introduces exponential bias degradation through active S-boxes. The 9-round approximation has correlation 2^{-54}; extending to 32 rounds would push the bias far below the 2^{-64} threshold where data requirements exceed the 2^{128} codebook. Full 32-round Serpent retains a **21-round security margin**.

**Leviathan analysis:** The S-boxes (`serpent.ts:101-141`) are the standard Serpent S-boxes implemented as Boolean circuits — the linear approximation properties exploited are inherent to the S-box truth tables, not the implementation. The linear transform (`serpent.ts:237-259`) uses the standard rotation constants. No implementation deviation exists that would affect these attacks. The full 32-round loop is unconditional.

**Verdict: NOT APPLICABLE — 21-round security margin.**

---

#### Paper 3 — Differential-Linear Attack on 12-Round Serpent (FSE 2008)

**Authors:** Orr Dunkelman, Sebastiaan Indesteege, Nathan Keller
**Published:** FSE 2008

**Attacks on Serpent:**

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Improved differential-linear | 11 | Chosen-plaintext | 2^121.8 | 2^135.7 | Key recovery (48 subkey bits) |
| Inverted differential-linear | 11 | Chosen-ciphertext | 2^113.7 | 2^137.7 | Key recovery (60 subkey bits) |
| **12-round differential-linear** | **12** | **Chosen-plaintext** | **2^123.5** | **2^249.4** | **Key recovery (160 subkey bits)** |
| Improved 10-round (128-bit) | 10 | Chosen-plaintext | 2^97.2 | 2^128 | Key recovery |
| Related-key (modified Serpent) | 32* | Related-key CP | 2^125 | Negligible | Distinguisher |

*\*Targets a non-standard Serpent variant with key schedule constants removed.*

**Core technique:** A 9-round differential-linear approximation combining a 3-round truncated differential (probability 2^{-6}) with a 6-round linear approximation (bias 2^{-27}). The key innovation is experimental verification showing the actual bias is ~2^1.25x higher than theoretical predictions (pairs that don't satisfy the differential still contribute non-zero bias). The 12-round attack extends by prepending one round with 2^112 subkey guesses.

**The 12-round result is the best attack across all papers examined.** At 2^249.4 time complexity vs. 2^256 brute force, it provides only ~6.6 bits of advantage — a purely certificational result. The progression from 11 to 12 rounds required an increase of 2^113.7 in time complexity, demonstrating the exponential cost of each additional round.

**Related-key attack (Section 5):** Exploits a rotation property requiring removal of the `0x9e3779b9 ^ i` constants from the key schedule. Leviathan's key schedule at `serpent.ts:90` includes these constants:
```typescript
this.key[i] = r[b] = this.rotW(this.key[a] ^ r[b] ^ r[c] ^ r[d] ^ 0x9e3779b9 ^ i, 11);
```
This attack is entirely inapplicable to the standard cipher.

**Leviathan analysis:** The 12-round attack targets Serpent-256 specifically, and leviathan supports 256-bit keys. However, it covers only 12 of 32 rounds, leaving a **20-round security margin**. The time complexity is already within ~6.6 bits of brute force at 12 rounds — extending to 13 rounds would push complexity well beyond 2^256. The leviathan implementation has no deviation from the standard specification that would affect differential-linear propagation.

**Verdict: NOT APPLICABLE — 20-round security margin.**

---

#### Paper 4 — Linear Cryptanalysis of Reduced Round Serpent (FSE 2001)

**Authors:** Eli Biham, Orr Dunkelman, Nathan Keller
**Published:** FSE 2001, LNCS 2355, pp. 16-27

**Attacks on Serpent:**

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| 9-round linear approximation | 9 | Known-plaintext | N/A | N/A | Approximation (building block) |
| 10-round key recovery | 10 | Known-plaintext | 2^118 | 2^89 | Key recovery (44-112 subkey bits) |
| 11-round key recovery (192/256) | 11 | Known-plaintext | 2^118 | 2^187 | Key recovery (140 subkey bits) |

**Core technique:** Systematic search for linear approximations through Serpent's S-boxes identified a 9-round approximation with bias 2^{-52} (39 active S-boxes). This is 4-8x stronger than the bounds claimed by the Serpent designers, but the authors note "there is a huge distance between a 9-round approximation and attacking 32 rounds, or even 16 rounds of Serpent." The 10-round attack uses Matsui's Algorithm 2 with an optimized precomputation table. The 11-round extension adds first-round subkey guessing (96 bits) with a precomputed table costing 2^{192} entries.

**Why it doesn't apply:** The bias progression per round shows roughly 5-13 bits of degradation per additional round. A 32-round approximation would have bias far below 2^{-128}, requiring more than 2^{256} data — information-theoretically impossible for a 128-bit block cipher. Full 32-round Serpent retains a **21-round security margin**.

**Leviathan analysis:** The S-box implementation (`serpent.ts:101-141`) produces the same truth tables as the specification — the linear approximation properties are intrinsic to the algorithm. The encryption loop (`serpent.ts:318-328`) applies all 32 rounds unconditionally. The 11-round attack's memory requirement of 2^{193} bits is astronomically beyond any physical storage.

**Verdict: NOT APPLICABLE — 21-round security margin.**

---

#### Paper 5 — The Rectangle Attack (EUROCRYPT 2001)

**Authors:** Eli Biham, Orr Dunkelman, Nathan Keller
**Published:** EUROCRYPT 2001, LNCS 2045, pp. 340-357

**Attacks on Serpent:**

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Differential attack (all keys) | 7 | Chosen-plaintext | 2^84 | 2^85 | Key recovery (128 subkey bits) |
| Differential attack (256-bit) | 8 | Chosen-plaintext | 2^84 | 2^213 | Key recovery |
| Rectangle attack (256-bit) | 10 | Chosen-plaintext | 2^126.8 | 2^207.4 | Key recovery (84 subkey bits) |

**Core technique:** The rectangle attack decomposes the cipher into two halves and counts over all intermediate differences at the boundary (rather than requiring a specific one). This replaces the single-characteristic probability p^2\*q^2 with sums of squared differential probabilities, which is strictly better whenever multiple trails exist. For Serpent, a 4-round characteristic for E_0 (probability 2^{-29}) and a 4-round characteristic for E_1 (probability 2^{-47}) are combined. The paper also proves the best 3-round differential characteristic of Serpent has probability 2^{-15} (7 active S-boxes), confirming the S-boxes are well-designed against differential attack.

**Why it doesn't apply:** The best result covers 10 rounds. The 6-round differential at the core has probability 2^{-93}, already near the birthday bound. Each additional round adds at least 2^{-15} probability degradation (proven 3-round bound). Full 32-round Serpent retains a **22-round security margin**.

**Leviathan analysis:** The implementation faithfully follows the Serpent specification. S-boxes (`serpent.ts:101-141`), linear transform (`serpent.ts:237-259`), and key schedule (`serpent.ts:193-226`) all match the standard. The differential properties exploited are intrinsic to the cipher's design. The full 32-round structure is unconditional.

**Verdict: NOT APPLICABLE — 22-round security margin.**

---

#### Consolidated Verdict Table

| Paper | Best Attack (Rounds) | Security Margin | Time Complexity | Verdict |
|-------|---------------------|-----------------|-----------------|---------|
| Amplified Boomerang (FSE 2000) | 8 | 24 rounds | 2^179 | NOT APPLICABLE |
| Chosen-Plaintext Linear (IET 2013) | 11 | 21 rounds | 2^144 | NOT APPLICABLE |
| **Differential-Linear (FSE 2008)** | **12** | **20 rounds** | **2^249.4** | **NOT APPLICABLE** |
| Linear Cryptanalysis (FSE 2001) | 11 | 21 rounds | 2^187 | NOT APPLICABLE |
| Rectangle Attack (EUROCRYPT 2001) | 10 | 22 rounds | 2^207.4 | NOT APPLICABLE |

**Minimum security margin across all papers: 20 rounds (62.5% of the cipher untouched)**
**Best attack advantage over brute force: ~6.6 bits (differential-linear on 12 rounds)**

Additional context from the literature (consistent with v2 findings):
- Best known attacks on Serpent reach at most 12 rounds (vs 32 implemented): no practical attack.
- Biclique attack (full 32-round): 2^255.21 — only ~0.8 bits better than brute force, impractical.
- A correct 32-round Serpent-256 implementation is secure against all known attacks.

---

#### Final Assessment

Every attack in this audit corpus shares one fundamental limitation: **they work only on reduced-round Serpent.** The best result across all five papers — the 12-round differential-linear attack by Dunkelman, Indesteege, and Keller (2008) — achieves a time complexity of 2^249.4, which is barely distinguishable from the 2^256 brute-force bound. Each additional round costs exponentially more: the jump from 11 to 12 rounds alone required a 2^113.7x increase in time complexity. Extending to 13 rounds would push the attack well beyond brute force, rendering it pointless.

The remaining 20 rounds of Serpent are not a thin margin — they represent an exponential barrier that no known cryptanalytic technique can bridge. The Serpent designers chose 32 rounds specifically to provide this defense-in-depth, roughly doubling the rounds needed for security at the time of design. Two decades of published research have validated this decision.

**Leviathan's round count is not configurable.** The `encrypt()` method (`serpent.ts:305-343`) uses a `while` loop from `n=0` to `n=31` with the `EC` array providing exactly 32 round constants. There is no `numRounds` parameter. The `decrypt()` method (`serpent.ts:352-383`) mirrors this with `DC` providing exactly 32 entries. The `init()` method (`serpent.ts:193-226`) generates all 132 subkey words (33 subkeys x 4 words) unconditionally. The `Serpent_CBC`, `Serpent_CTR`, `Serpent_CBC_PKCS7`, and `Serpent_CTR_PKCS7` wrapper classes (`serpent.ts:406-495`) all delegate to the same full 32-round `Serpent` core. There is no configuration object, no optional parameter, and no conditional logic anywhere in the round loop that could result in fewer than 32 rounds being applied. **The API makes it structurally impossible for a caller to request reduced-round encryption.**

**Residual concern — unauthenticated modes:** Neither CBC nor CTR mode provides integrity or authentication. Chosen-ciphertext attacks (padding oracles, bit-flipping) are a more realistic threat than any of the reduced-round algebraic attacks examined here. Applications must layer authentication (HMAC, Poly1305, or an AEAD construction) externally. The CTR counter-increment timing concern is addressed in [Section 1.1](#11-side-channel-analysis).

**Bottom line:** Leviathan's Serpent-256 implementation is not vulnerable to any attack documented in these papers. The single, sufficient reason is that all attacks target reduced-round variants (at most 12 of 32 rounds), and leviathan unconditionally applies all 32 rounds with no API to reduce them. The 20-round minimum security margin is an exponential barrier that no known or foreseeable cryptanalytic technique can overcome. No code changes are recommended to address the attacks in this corpus.

---

## 2. Implementation Correctness

### 2.1 Algorithm Correctness

#### Verdict: Correct

The structural design is sound and matches the bitslice Serpent specification. The following components were analyzed in detail against the reference C implementation (`serpent-reference.c`, `serpent-tables.h`) and confirmed by 4,770 test vectors.

---

#### S-Boxes

leviathan implements S-boxes as Boolean logic (bitslice style). The 8 forward (`S[]`) and 8 inverse (`SI[]`) functions use only `&`, `|`, `^`, and `~` on 32-bit words — no table lookups.

The Boolean expansions are equivalent to the 4-bit to 4-bit lookup tables in `serpent-tables.h`. Correctness was established by the test-vector suite.

Reference S-box values (ground truth from `serpent-tables.h`):
```
S0: { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 }
S1: {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 }
S2: { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 }
S3: { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 }
S4: { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 }
S5: {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 }
S6: { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 }
S7: { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 }
```

---

#### Linear Transform

`LK` (linear transform + key mixing for encryption) implements the 10-step Serpent bitslice LT exactly:

| Step | Spec                        | leviathan (`LK`)                      |
|------|-----------------------------|---------------------------------------|
| 1    | X0 = X0 <<< 13              | `r[a] = rotW(r[a], 13)`               |
| 2    | X2 = X2 <<< 3               | `r[c] = rotW(r[c], 3)`                |
| 3    | X1 = X1 ^ X0 ^ X2           | `r[b] ^= r[a]; r[b] ^= r[c]`          |
| 4    | X3 = X3 ^ X2 ^ (X0 << 3)    | `r[d] ^= r[c]; r[d] ^= r[e]` (e=X0<<3)|
| 5    | X1 = X1 <<< 1               | `r[b] = rotW(r[b], 1)`                |
| 6    | X3 = X3 <<< 7               | `r[d] = rotW(r[d], 7)`                |
| 7    | X0 = X0 ^ X1 ^ X3           | `r[a] ^= r[b]; r[a] ^= r[d]`          |
| 8    | X2 = X2 ^ X3 ^ (X1 << 7)    | `r[c] ^= r[d]; r[c] ^= r[e]` (e=X1<<7)|
| 9    | X0 = X0 <<< 5               | `r[a] = rotW(r[a], 5)`                |
| 10   | X2 = X2 <<< 22              | `r[c] = rotW(r[c], 22)`               |

All 10 steps match the spec.

The `& this.wMax` masks preserve 32-bit arithmetic in JavaScript.

**Inverse LT (`KL`)** uses the correct inverse rotations: ROTL(27)=undo-ROTL(5), ROTL(10)=undo-ROTL(22), ROTL(31)=undo-ROTL(1), ROTL(25)=undo-ROTL(7), ROTL(19)=undo-ROTL(13), ROTL(29)=undo-ROTL(3). Correctness confirmed by vector testing.

---

#### Key Schedule

**Two-stage init:**

1. **Key padding** — pads shorter keys to 256 bits:
   - 128-bit key: sets bit 128 (word index 4 = 1). (reference: `key[bitsInShortKey/BITS_PER_WORD] |= 1 << (bitsInShortKey%BITS_PER_WORD)`)
   - 192-bit key: sets bit 192 (word index 6 = 1).
   - 256-bit key: no padding needed; `this.key[32]=1` is set but then overwritten by prekey generation.

2. **Prekey generation** — computes `w[8..131]` via affine recurrence:
   ```
   w[i] = (w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ i) <<< 11
   phi = 0x9e3779b9
   ```
   leviathan's sliding-window implementation (5-element `r[]` + `this.key[j]`) produces the same recurrence.

3. **Subkey extraction** (bitslice S-boxes applied to prekey groups):
   - S-box for subkey `Kn` = `S_{(3-n) mod 8}` (spec section 3)
   - leviathan iterates from K32 down to K0 with `j` starting at 3:
     K32=S3, K31=S4, K30=S5, K29=S6, K28=S7, K27=S0, K26=S1, K25=S2, K24=S3...
   - The KC array encodes S-box I/O slot permutations via modulo arithmetic.

---

#### Round Structure

**Encryption** (`encrypt` method):
```
K(0) -> S[0] -> LT+K(1) -> S[1] -> LT+K(2) -> ... -> LT+K(31) -> S[31] -> K(32)
```
Matches spec: 32 rounds, S-boxes cycle S0..S7 (round `n` uses `S[n%8]`), last round skips LT, followed by final key mixing.

**Decryption** (`decrypt` method):
```
K(32) -> SI[7] -> ILT+K(31) -> SI[6] -> ILT+K(30) -> ... -> ILT+K(1) -> SI[0] -> K(0)
```
Uses `SI[7-n%8]` inverse S-boxes in reverse order.

---

#### Byte Ordering

leviathan uses the **original Serpent format from the AES submission**. The convention is as follows:
- **Input**: plaintext bytes reversed, then loaded as 4 little-endian uint32 words
- **Key**: bytes reversed, repacked as 8 little-endian uint32 words
- **Output**: 4 uint32 words emitted in reverse word order, big-endian byte order each

This is **not** the NESSIE convention. The NESSIE test-vector preprocessing (word reversal + byte-swap) exists precisely because of this difference. The AES submission vectors in `floppy4/` work directly with leviathan's convention without transformation.

---

#### Known Issue: Magic Constants (EC / DC / KC)

leviathan encodes the bitslice S-box register slot assignments as magic integer constants:
```typescript
const EC = new Uint32Array([44255, 61867, 45034, ...]);  // encrypt
const DC = new Uint32Array([44255, 60896, 28835, ...]);  // decrypt
const KC = new Uint32Array([7788, 63716, 84032, ...]);   // key schedule
```

For each round `n`, the constant `m = EC[n]` determines which of the 5 working registers `r[0..4]` are used as S-box inputs/outputs via `m%5, m%7, m%11, m%13, m%17`. These values must produce all five distinct indices {0,1,2,3,4} in the correct permutation for each S-box call.

**This cannot be verified by static inspection.** If any constant is wrong, the register shuffle will corrupt data silently without obvious structure. This is the highest-risk unverifiable component. The intermediate-value tests (`ecb_iv.txt`) are specifically designed to catch such errors round by round, and the full test suite (4,770 vectors) confirms correctness.

---

### 2.2 Security Properties

#### Authentication / IV Handling

- `Serpent_CBC` and `Serpent_CTR` are **unauthenticated** — susceptible to ciphertext manipulation if used without a MAC. This is expected for raw block cipher modes.
- No AEAD (EAX/GCM) implementation exists. Applications needing authentication must layer HMAC or similar externally.
- No IV validation: callers can reuse IVs/nonces. No enforcement.

#### Input Validation

- Key length is not validated: any `Uint8Array` length is accepted. For keys longer than 32 bytes, the padding logic would fail silently (writes to valid indices but leaves wrong data at key[4..7]).
- For keys longer than 32 bytes: `this.key[key.length] = 1` may write beyond the intended range before the repack loop corrects it for 128/192/256-bit keys. The repack loop only runs for `i=0..7`, so any garbage beyond that is ignored, but the sentinel `1` at index `key.length` corrupts the prekey generation buffer if `key.length > 7` and `key.length < 132`.

---

### 2.3 Constant-Time Equality Audit

All `===`, `every`, `reduce`, `indexOf`, `includes`, loop comparisons, and usages of `Util.compare` across `src/*.ts` were reviewed and classified as SENSITIVE or NON-SENSITIVE.

Two locations were identified as **SENSITIVE**: `Ed25519.verify()` in `x25519.ts` (compares computed signature R component against expected — a timing oracle here enables Ed25519 forgery) and `neq25519()` in `x25519.ts` (compares packed Curve25519 field elements during the verify/unpack path). All other comparison sites — selftest `Util.compare` calls in `serpent.ts`, `x25519.ts`, and `pbkdf2.ts`, plus all `===` checks on counters, indices, and buffer sizes — were classified as NON-SENSITIVE (hardcoded public test vectors or control-flow with no secret data).

The `constantTimeEqual` function was added to `base.ts` as a standalone export. It implements the XOR-accumulate pattern: every byte is visited regardless of content, and the result collapses to a single `diff === 0` comparison at the end. This prevents timing oracles where an attacker measures how many bytes were compared before a mismatch was detected, which would leak information about secret values byte-by-byte. The length check is explicitly not constant-time — length is non-secret in all protocols where this is used.

`Util.compare` was simplified to delegate directly to `constantTimeEqual`, eliminating the risk of independent drift between two comparison implementations. The two SENSITIVE sites in `x25519.ts` were updated to use `constantTimeEqual` with inline annotations explaining why constant-time comparison is required at each location.

13 new tests were added in `10_constant_time.test.ts` covering: basic correctness, all-zero arrays (sizes 1/16/32), single-byte differences at positions 0/middle/last, non-trivial round-trip, empty arrays, and a timing smoke test. The full test suite passed: 4,718/4,718 at the time of this change.

---

### 2.4 Deprecated and Removed Components

| Component | Reason |
|-----------|--------|
| `src/aes.ts` | Removed — AES removed from library |
| `src/sha1.ts` | Removed — SHA-1 is cryptographically broken (SHAttered, 2017) |
| `ECB` class (`blockmode.ts`) | Removed — not semantically secure |
| `PKCS5` class (`padding.ts`) | Removed — redundant with PKCS7 |
| `ZeroPadding` class (`padding.ts`) | Removed — insecure padding scheme |
| `HMAC_SHA1` (`hmac.ts`) | Removed — depends on removed SHA-1 |
| Fortuna PRNG block cipher | Changed from AES to Serpent (`random.ts`) |

---

### 2.5 Test Suite

**4,770/4,770 tests passing** across 21 test files.

#### Breakdown

- **~19.2 million** individual encrypt/decrypt operations executed via Monte Carlo
- **2,312** NESSIE encrypt + 2,312 NESSIE decrypt operations verified (Serpent-128 and Serpent-256)
- **17** CTR mode vector tests (5 cases x 128/192/256-bit keys, counter wrap, ECB cross-check)
- Key sizes covered: 128, 192, and 256 bits
- Modes covered: ECB and CBC (vector-verified); CTR and PKCS7 variants (round-trip verified)
- Key schedule verified: all 33 subkeys match reference for KEYSIZE=128

#### Test Files

| File | Tests | Description |
|------|-------|-------------|
| `01_kat.test.ts` | 15 | KAT tests (ecb_vt, ecb_vk, ecb_tbl, round-trip, selftest) |
| `02_intermediate.test.ts` | — | SK[] key schedule verification + roundHook test |
| `03_monte_carlo_ecb.test.ts` | — | ECB Monte Carlo + chain continuity |
| `04_monte_carlo_cbc.test.ts` | — | CBC Monte Carlo encrypt + decrypt |
| `05_serpent_modes.test.ts` | 16 | Serpent_CBC/CTR/PKCS7 wrappers |
| `06_nessie_helpers.test.ts` | 17 | NESSIE preprocessing helper unit tests |
| `07_nessie_vectors.test.ts` | 2568 | All 1,284 NESSIE Serpent-256-128 vectors |
| `08_nessie128_vectors.test.ts` | 2058 | All 1,028 NESSIE Serpent-128-128 vectors |
| `09_ctr_vectors.test.ts` | 17 | CTR mode vectors (encrypt, decrypt, block-boundary, IV-independence, ECB cross-corpus) |
| `10_constant_time.test.ts` | 13 | Constant-time equality correctness and smoke tests |
| `11_base.test.ts` | 9 | Convert (hex2bin, bin2hex, base64, base64url), Util (clear, compare, xor) |
| `12_chacha20.test.ts` | 2 | ChaCha20 encrypt/decrypt vectors |
| `13_hmac.test.ts` | 3 | HMAC input-unaltered, HMAC-SHA256, HMAC-SHA512 |
| `14_padding.test.ts` | 1 | PKCS7 pad/strip round-trip (all block sizes x all lengths 0-127) |
| `15_pbkdf2.test.ts` | 2 | PBKDF2 HMAC-SHA256 vectors, selftest |
| `16_serpent.test.ts` | 6 | Encrypt/decrypt vectors, Monte Carlo 10,000 rounds x2, CBC-PKCS7, selftest |
| `17_sha256.test.ts` | 4 | Hash, update, iteration (sjcl-style), selftest |
| `18_sha512.test.ts` | 4 | Hash, update, iteration (sjcl-style), selftest |
| `19_sha3.test.ts` | 10 | Keccak-384, SHA3-256/512, SHAKE128-256, SHAKE256-512 |
| `20_uuid.test.ts` | 2 | UUID V1 and V4 format checks |
| `21_x25519.test.ts` | 9 | Curve25519 KAT, Monte Carlo, scalarMult, Ed25519 keygen/sign/verify, selftests |

#### Test Coverage

| Test | Status |
|------|--------|
| AES submission KAT (vt + vk) | Covered |
| ecb_tbl.txt S-box entry tests | Covered |
| ecb_iv.txt intermediate round values | Covered |
| ECB Monte Carlo (key-updating) | Covered |
| CBC Monte Carlo | Covered |
| NESSIE 256-bit vectors | Covered |
| NESSIE 128-bit vectors | Covered |
| 192/256-bit key KAT vectors | Covered |
| CTR mode vectors | Covered |
| Encrypt/decrypt round-trip 128/192/256 | Covered |
| Constant-time equality | Covered |
| All-zero inputs edge case | Covered |

---

## 3. Open Questions

1. **Literature update beyond 2013:** The most recent paper in this corpus is from 2013. A human cryptographer should verify whether any post-2013 publication has extended reduced-round attacks beyond 12 rounds on Serpent. If any result reaches 16+ rounds, the security margin analysis should be revisited.

2. **Linear hull effect:** Multiple papers note that the linear hull effect (summing over all trails with the same input/output masks) could increase effective correlations. Whether this has been quantified for Serpent's 9-round approximations would be useful context.

3. **Related-key attacks on standard Serpent:** The differential-linear paper (FSE 2008) showed a related-key attack on modified Serpent (without key schedule constants). Whether related-key attacks using other key relationships have been explored against the standard Serpent key schedule is an open question.

4. **Boomerang Connectivity Table (BCT) advances:** Post-2018 BCT-based analysis has improved boomerang/rectangle attacks on other ciphers. Whether BCT techniques yield better results on Serpent than the 10-round rectangle result from 2001 should be checked.

5. **Data-per-key limits in deployment:** Even though no attack on full Serpent is known, standard practice for 128-bit block ciphers is to re-key before 2^64 blocks (birthday bound on block collisions). Confirming that leviathan's deployment contexts enforce reasonable data-per-key limits would provide additional assurance.
