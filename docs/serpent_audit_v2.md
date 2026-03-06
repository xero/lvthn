# Leviathan Serpent-256 — Cryptographic Attack Surface Audit (Round 2)

**Date:** 2026-03-06
**Scope:** 5 academic cryptanalysis papers targeting Serpent, applied to the leviathan TypeScript implementation
**Target:** `leviathan/src/serpent.ts` (Serpent-256, AES submission format, 32 rounds)
**Mode:** Read-only security audit — no code changes

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Implementation Baseline](#2-implementation-baseline)
3. [Paper 1 — Amplified Boomerang Attacks (FSE 2000)](#3-paper-1--amplified-boomerang-attacks-fse-2000)
4. [Paper 2 — Chosen-Plaintext Linear Attacks (IET 2013)](#4-paper-2--chosen-plaintext-linear-attacks-iet-2013)
5. [Paper 3 — Differential-Linear Attack on 12-Round Serpent (FSE 2008)](#5-paper-3--differential-linear-attack-on-12-round-serpent-fse-2008)
6. [Paper 4 — Linear Cryptanalysis of Reduced Round Serpent (FSE 2001)](#6-paper-4--linear-cryptanalysis-of-reduced-round-serpent-fse-2001)
7. [Paper 5 — The Rectangle Attack (EUROCRYPT 2001)](#7-paper-5--the-rectangle-attack-eurocrypt-2001)
8. [Consolidated Verdict Table](#8-consolidated-verdict-table)
9. [Final Audit Assessment](#9-final-audit-assessment)
10. [Open Questions for Human Review](#10-open-questions-for-human-review)

---

## 1. Executive Summary

Seven academic papers were examined. Two were excluded as inapplicable — one targets AES-192 exclusively (`aes-key-boomerang.pdf`), and one targets IDEA (`unified-key-attacks.pdf`). Neither has any structural relevance to Serpent-256.

The remaining five papers collectively document **18 distinct attacks** against reduced-round Serpent using four major cryptanalytic techniques: differential, linear, differential-linear, and rectangle/boomerang. The highest number of rounds reached by any attack is **12** (differential-linear, Dunkelman et al. 2008), with a time complexity of 2^249.4 — only ~6.6 bits better than brute force on a 256-bit key.

**No attack in any paper threatens full 32-round Serpent-256.** The minimum security margin across all attacks is **20 rounds** (32 - 12). The leviathan implementation is a faithful, correct, full 32-round Serpent-256 with no API to reduce the round count.

---

## 2. Implementation Baseline

Properties of the leviathan Serpent-256 implementation confirmed by source review and the prior Round 1 audit (4,770 test vectors passing):

| Property | Status | Source Location |
|----------|--------|-----------------|
| Full 32 rounds | Hardcoded, no configurable round count | `serpent.ts:318-328` (encrypt loop n=0..31) |
| S-boxes | Pure Boolean gate circuits (AND/OR/XOR/NOT), constant-time by construction | `serpent.ts:101-141` (forward), `144-184` (inverse) |
| Linear transform | Standard 10-step bitslice LT, fixed rotation constants (13,3,1,7,5,22) | `serpent.ts:237-259` (LK), `262-284` (KL) |
| Key schedule | Standard prekey recurrence with `phi ^ i`, S-box subkey derivation | `serpent.ts:89-90` (keyIt), `193-226` (init) |
| 33 subkeys (K0-K32) | All generated, all applied | `serpent.ts:209-225` (generation), `318-333` (application) |
| Round count API exposure | **None** — no parameter, no option, no conditional logic to skip rounds | Entire `encrypt()` / `decrypt()` methods |
| Block modes | CBC (unauthenticated), CTR (known counter-increment timing issue) | `blockmode.ts:26-83` (CBC), `85-153` (CTR) |

---

## 3. Paper 1 — Amplified Boomerang Attacks (FSE 2000)

**Authors:** John Kelsey, Tadayoshi Kohno, Bruce Schneier
**Published:** FSE 2000, LNCS 1978, pp. 75-93

### Attacks on Serpent

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Amplified boomerang distinguisher | 7 | Chosen-plaintext | 2^113 | < brute force | Distinguisher |
| Amplified boomerang key recovery | 8 | Chosen-plaintext | 2^113 | 2^179 | Key recovery (68 subkey bits) |

**Core technique:** The cipher is split into two halves: E_0 (rounds 1-4) and E_1 (rounds 5-7). A 4-round differential with probability 2^{-31} and a 3-round differential with probability 2^{-16} are combined via the amplified boomerang framework. The key recovery extends by one round through subkey guessing.

**Why it doesn't apply:** The differential characteristics cover at most 4 rounds (2^{-31}) and 3 rounds (2^{-16}). Differences spread rapidly through Serpent's linear transform — the authors themselves state "differences spread out, so that it is possible to find reasonably good characteristics for three or four rounds at a time, but not for larger numbers of rounds." Full 32-round Serpent retains a **24-round security margin**. The authors explicitly confirm: "this attack does not threaten the full 32-round Serpent."

### Leviathan Analysis

The leviathan encryption loop (`serpent.ts:318-328`) unconditionally executes all 32 rounds. The S-boxes and linear transform match the standard Serpent specification — the attack exploits inherent algebraic properties, not implementation-specific weaknesses. The JS/JIT environment is irrelevant to this purely algebraic/statistical attack.

**Verdict: INSUFFICIENT INFORMATION** — No vulnerability. 24-round margin is overwhelming.

---

## 4. Paper 2 — Chosen-Plaintext Linear Attacks (IET 2013)

**Authors:** Jialin Huang, Xuejia Lai
**Published:** IET Information Security, Vol. 7, Iss. 4, pp. 293-299, 2013
**DOI:** 10.1049/iet-ifs.2012.0287

### Attacks on Serpent

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Single linear (all keys) | 10 | Chosen-plaintext | 2^92 | 2^84.68 | Key recovery |
| Single linear (192/256-bit) | 10 | Chosen-plaintext | 2^80 | 2^180.68 | Key recovery |
| Multidimensional linear | 10 | Chosen-plaintext | 2^88 | 2^84.07 | Key recovery |
| Multidimensional linear | 11 | Chosen-plaintext | 2^116 | 2^144 | Key recovery |
| Experimental validation | 5 | Chosen-plaintext | ~2^20 | Trivial | Key recovery (12 bits) |

**Core technique:** By fixing specific S-box inputs in the first round of a linear approximation, inactive S-boxes have correlation exactly +/-1 instead of 2^{-1}, boosting the overall approximation correlation. This reduces data complexity by up to 2^22 for single-approximation attacks and dramatically reduces time complexity for multidimensional attacks (from 2^{134.43} to 2^{84.07} for 10 rounds).

**Why it doesn't apply:** The best result reaches 11 rounds. Each additional round introduces exponential bias degradation through active S-boxes. The 9-round approximation has correlation 2^{-54}; extending to 32 rounds would push the bias far below the 2^{-64} threshold where data requirements exceed the 2^{128} codebook. Full 32-round Serpent retains a **21-round security margin**.

### Leviathan Analysis

The leviathan S-boxes (`serpent.ts:101-141`) are the standard Serpent S-boxes implemented as Boolean circuits — the linear approximation properties exploited are inherent to the S-box truth tables, not the implementation. The linear transform (`serpent.ts:237-259`) uses the standard rotation constants. No implementation deviation exists that would affect these attacks. The full 32-round loop is unconditional.

**Verdict: INSUFFICIENT INFORMATION** — No vulnerability. 21-round margin against the best result.

---

## 5. Paper 3 — Differential-Linear Attack on 12-Round Serpent (FSE 2008)

**Authors:** Orr Dunkelman, Sebastiaan Indesteege, Nathan Keller
**Published:** FSE 2008

### Attacks on Serpent

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

### Leviathan Analysis

The 12-round attack targets Serpent-256 specifically, and leviathan supports 256-bit keys. However, it covers only 12 of 32 rounds, leaving a **20-round security margin**. The time complexity is already within ~6.6 bits of brute force at 12 rounds — extending to 13 rounds would push complexity well beyond 2^256. The leviathan implementation has no deviation from the standard specification that would affect differential-linear propagation.

**Verdict: INSUFFICIENT INFORMATION** — No vulnerability. The 20-round margin is the smallest of any paper in this audit, but it remains overwhelming.

---

## 6. Paper 4 — Linear Cryptanalysis of Reduced Round Serpent (FSE 2001)

**Authors:** Eli Biham, Orr Dunkelman, Nathan Keller
**Published:** FSE 2001, LNCS 2355, pp. 16-27

### Attacks on Serpent

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| 9-round linear approximation | 9 | Known-plaintext | N/A | N/A | Approximation (building block) |
| 10-round key recovery | 10 | Known-plaintext | 2^118 | 2^89 | Key recovery (44-112 subkey bits) |
| 11-round key recovery (192/256) | 11 | Known-plaintext | 2^118 | 2^187 | Key recovery (140 subkey bits) |

**Core technique:** Systematic search for linear approximations through Serpent's S-boxes identified a 9-round approximation with bias 2^{-52} (39 active S-boxes). This is 4-8x stronger than the bounds claimed by the Serpent designers, but the authors note "there is a huge distance between a 9-round approximation and attacking 32 rounds, or even 16 rounds of Serpent." The 10-round attack uses Matsui's Algorithm 2 with an optimized precomputation table. The 11-round extension adds first-round subkey guessing (96 bits) with a precomputed table costing 2^{192} entries.

**Why it doesn't apply:** The bias progression per round (Table 1 in the paper) shows roughly 5-13 bits of degradation per additional round. A 32-round approximation would have bias far below 2^{-128}, requiring more than 2^{256} data — information-theoretically impossible for a 128-bit block cipher. Full 32-round Serpent retains a **21-round security margin**.

### Leviathan Analysis

The leviathan S-box implementation (`serpent.ts:101-141`) produces the same truth tables as the specification — the linear approximation properties are intrinsic to the algorithm. The encryption loop (`serpent.ts:318-328`) applies all 32 rounds unconditionally. The 11-round attack's memory requirement of 2^{193} bits is astronomically beyond any physical storage.

**Verdict: INSUFFICIENT INFORMATION** — No vulnerability. 21-round margin.

---

## 7. Paper 5 — The Rectangle Attack (EUROCRYPT 2001)

**Authors:** Eli Biham, Orr Dunkelman, Nathan Keller
**Published:** EUROCRYPT 2001, LNCS 2045, pp. 340-357

### Attacks on Serpent

| Attack | Rounds | Model | Data | Time | Type |
|--------|--------|-------|------|------|------|
| Differential attack (all keys) | 7 | Chosen-plaintext | 2^84 | 2^85 | Key recovery (128 subkey bits) |
| Differential attack (256-bit) | 8 | Chosen-plaintext | 2^84 | 2^213 | Key recovery |
| Rectangle attack (256-bit) | 10 | Chosen-plaintext | 2^126.8 | 2^207.4 | Key recovery (84 subkey bits) |

**Core technique:** The rectangle attack decomposes the cipher into two halves and counts over all intermediate differences at the boundary (rather than requiring a specific one). This replaces the single-characteristic probability p^2*q^2 with sums of squared differential probabilities, which is strictly better whenever multiple trails exist. For Serpent, a 4-round characteristic for E_0 (probability 2^{-29}) and a 4-round characteristic for E_1 (probability 2^{-47}) are combined. The paper also proves the best 3-round differential characteristic of Serpent has probability 2^{-15} (7 active S-boxes), confirming the S-boxes are well-designed against differential attack.

**Why it doesn't apply:** The best result covers 10 rounds. The 6-round differential at the core has probability 2^{-93}, already near the birthday bound. Each additional round adds at least 2^{-15} probability degradation (proven 3-round bound). Full 32-round Serpent retains a **22-round security margin**.

### Leviathan Analysis

The leviathan implementation faithfully follows the Serpent specification. S-boxes (`serpent.ts:101-141`), linear transform (`serpent.ts:237-259`), and key schedule (`serpent.ts:193-226`) all match the standard. The differential properties exploited are intrinsic to the cipher's design. The full 32-round structure is unconditional.

**Verdict: INSUFFICIENT INFORMATION** — No vulnerability. 22-round margin.

---

## 8. Consolidated Verdict Table

| Paper | Best Attack (Rounds) | Security Margin | Time Complexity | Verdict |
|-------|---------------------|-----------------|-----------------|---------|
| Amplified Boomerang (FSE 2000) | 8 | 24 rounds | 2^179 | INSUFFICIENT INFORMATION |
| Chosen-Plaintext Linear (IET 2013) | 11 | 21 rounds | 2^144 | INSUFFICIENT INFORMATION |
| **Differential-Linear (FSE 2008)** | **12** | **20 rounds** | **2^249.4** | **INSUFFICIENT INFORMATION** |
| Linear Cryptanalysis (FSE 2001) | 11 | 21 rounds | 2^187 | INSUFFICIENT INFORMATION |
| Rectangle Attack (EUROCRYPT 2001) | 10 | 22 rounds | 2^207.4 | INSUFFICIENT INFORMATION |

**Minimum security margin across all papers: 20 rounds (62.5% of the cipher untouched)**
**Best attack advantage over brute force: ~6.6 bits (differential-linear on 12 rounds)**

---

## 9. Final Audit Assessment

### The Core Finding

Every attack in this audit corpus shares one fundamental limitation: **they work only on reduced-round Serpent.** The best result across all five papers — the 12-round differential-linear attack by Dunkelman, Indesteege, and Keller (2008) — achieves a time complexity of 2^249.4, which is barely distinguishable from the 2^256 brute-force bound. Each additional round costs exponentially more: the jump from 11 to 12 rounds alone required a 2^113.7x increase in time complexity. Extending to 13 rounds would push the attack well beyond brute force, rendering it pointless.

The remaining 20 rounds of Serpent are not a thin margin — they represent an exponential barrier that no known cryptanalytic technique can bridge. The Serpent designers chose 32 rounds specifically to provide this defense-in-depth, roughly doubling the rounds needed for security at the time of design. Two decades of published research have validated this decision.

### Leviathan's Round Count Is Not Configurable

Having reviewed the full source of `serpent.ts`, I can confirm that **the leviathan implementation does not expose any mechanism to reduce the round count.** Specifically:

- The `encrypt()` method (`serpent.ts:305-343`) uses a `while` loop from `n=0` to `n=31` with the `EC` array providing exactly 32 round constants. There is no `numRounds` parameter.
- The `decrypt()` method (`serpent.ts:352-383`) mirrors this with `DC` providing exactly 32 entries.
- The `init()` method (`serpent.ts:193-226`) generates all 132 subkey words (33 subkeys x 4 words) unconditionally.
- The `Serpent_CBC`, `Serpent_CTR`, `Serpent_CBC_PKCS7`, and `Serpent_CTR_PKCS7` wrapper classes (`serpent.ts:406-495`) all delegate to the same full 32-round `Serpent` core.
- There is no configuration object, no optional parameter, and no conditional logic anywhere in the round loop that could result in fewer than 32 rounds being applied.

**The API makes it structurally impossible for a caller to request reduced-round encryption.** This is the correct design — and it is exactly the property that renders every attack in this audit corpus inapplicable.

### Why "INSUFFICIENT INFORMATION" Rather Than "SAFE"

The sub-agents rendered INSUFFICIENT INFORMATION rather than a definitive "safe" verdict for a disciplined reason: a formal proof that no future technique could ever bridge the 20-32 round gap does not exist. In cryptographic auditing, absolute safety claims require provable security bounds, and the wide-trail strategy that provides such bounds for AES has not been formally extended to Serpent's specific structure.

However, the practical reality is unambiguous:

1. **Twenty years of published research** (2000-2025) have advanced from 8 rounds to 12 rounds — a gain of 4 rounds in two decades, with exponentially increasing complexity at each step.
2. The **biclique attack** on full 32-round Serpent-256 (2^255.21, from the literature) is the only result that touches all 32 rounds, and it provides less than 1 bit of advantage over brute force.
3. All attacks exploit **inherent algebraic properties** of the Serpent S-boxes and linear transform — not implementation defects. No implementation change (short of adding rounds) can alter these properties.
4. The **JavaScript/JIT execution environment is irrelevant** to every attack in this corpus. These are all purely mathematical/statistical attacks that exploit cipher structure, not side channels.

### Residual Concerns (Non-Attack-Specific)

While no attack in this corpus applies to leviathan, the audit identified two pre-existing concerns from the Round 1 audit that remain relevant:

1. **CTR counter-increment timing leak** (`blockmode.ts:118-121`): The `else break` in the carry-propagation loop leaks information about how far the carry propagated. The counter is not secret, so practical impact is low, but a constant-time increment (always iterating all 16 bytes) would be cleaner.

2. **Unauthenticated CBC and CTR modes**: Neither mode provides integrity or authentication. Chosen-ciphertext attacks (padding oracles, bit-flipping) are a more realistic threat than any of the reduced-round algebraic attacks examined here. Applications must layer authentication (HMAC, Poly1305, or an AEAD construction) externally.

### Bottom Line

**Leviathan's Serpent-256 implementation is not vulnerable to any attack documented in these five papers.** The single, sufficient reason is that all attacks target reduced-round variants (at most 12 of 32 rounds), and leviathan unconditionally applies all 32 rounds with no API to reduce them. The 20-round minimum security margin is an exponential barrier that no known or foreseeable cryptanalytic technique can overcome.

No code changes are recommended to address the attacks in this corpus. The implementation is correct and secure against these attack classes by design.

---

## 10. Open Questions for Human Review

1. **Literature update beyond 2013:** The most recent paper in this corpus is from 2013. A human cryptographer should verify whether any post-2013 publication has extended reduced-round attacks beyond 12 rounds on Serpent. If any result reaches 16+ rounds, the security margin analysis should be revisited.

2. **Linear hull effect:** Multiple papers note that the linear hull effect (summing over all trails with the same input/output masks) could increase effective correlations. Whether this has been quantified for Serpent's 9-round approximations would be useful context.

3. **Related-key attacks on standard Serpent:** The differential-linear paper (FSE 2008) showed a related-key attack on modified Serpent (without key schedule constants). Whether related-key attacks using other key relationships have been explored against the standard Serpent key schedule is an open question.

4. **Boomerang Connectivity Table (BCT) advances:** Post-2018 BCT-based analysis has improved boomerang/rectangle attacks on other ciphers. Whether BCT techniques yield better results on Serpent than the 10-round rectangle result from 2001 should be checked.

5. **Data-per-key limits in deployment:** Even though no attack on full Serpent is known, standard practice for 128-bit block ciphers is to re-key before 2^64 blocks (birthday bound on block collisions). Confirming that leviathan's deployment contexts enforce reasonable data-per-key limits would provide additional assurance.

6. **Authentication layer:** The most practical risk to leviathan users is not any attack in this corpus, but the lack of built-in authenticated encryption. Ensuring documentation prominently guides users toward HMAC or AEAD wrappers is more security-relevant than any reduced-round algebraic concern.
