# State 66 Dedicated Validation Report

>[!NOTE]
> - **Date:** 2026-03-06
> - **Context:** Part of our [Biclique attack research against serpent256](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)
> - **Target:** Generator-set dim-4 biclique, Serpent-256
> - **Fixed biclique:** Delta_K nibble 6 of K31, Nabla_K nibble 11 of K18, states #91–#96

## 1. Construction

Source: [`BicliqueFinder/src/biclique/RunState66.java`](https://github.com/xero/BicliqueFinder/blob/main/BicliqueFinder/src/biclique/RunState66.java)

Four attacks run in a single execution:
- **Attack A:** state 66, nibble 8 (best single-nibble candidate from v-search)
- **Attack B:** state 66, nibble 9 (second-best candidate)
- **Reference:** state 75, nibble 31 (paper's published v)
- **Attack C:** state 66, nibbles 8+9 (multi-nibble, |v| = 8 bits)

All share identical biclique configuration and `SerpentFormula.GENERATOR_SET`.

---

## 2. Raw Output

### Attack A — State 66, Nibble 8
```
C_biclique  = 2^{0.74}
C_precomp   = 2^{3.92}
C_recomp    = 2^{6.99}
C_falpos    = 2^{4.00}
recomp_sboxes = 1036 (state=815 + key=221) / 2080
d = 4, 2d = 8
Is independent : true
time complexity : TimeComplexity = 2^{248} * 2^{7.32} = 2^{255.32}
data complexity : DataComplexity = 2^{4}
```

### Attack B — State 66, Nibble 9
```
C_biclique  = 2^{0.74}
C_precomp   = 2^{3.92}
C_recomp    = 2^{7.00}
C_falpos    = 2^{4.00}
recomp_sboxes = 1040 (state=818 + key=222) / 2080
d = 4, 2d = 8
Is independent : true
time complexity : TimeComplexity = 2^{248} * 2^{7.33} = 2^{255.33}
data complexity : DataComplexity = 2^{4}
```

### Reference — State 75, Nibble 31 (paper's v)
```
C_biclique  = 2^{0.74}
C_precomp   = 2^{3.92}
C_recomp    = 2^{7.08}
C_falpos    = 2^{4.00}
recomp_sboxes = 1097 (state=840 + key=257) / 2080
d = 4, 2d = 8
Is independent : true
time complexity : TimeComplexity = 2^{248} * 2^{7.39} = 2^{255.39}
data complexity : DataComplexity = 2^{4}
```

### Attack C — State 66, Nibbles 8+9
```
C_biclique  = 2^{0.74}
C_precomp   = 2^{3.92}
C_recomp    = 2^{7.03}
C_falpos    = 2^{0.00}
recomp_sboxes = 1059 (state=833 + key=226) / 2080
d = 4, 2d = 8
Is independent : true
time complexity : TimeComplexity = 2^{248} * 2^{7.21} = 2^{255.21}
data complexity : DataComplexity = 2^{4}
```

---

## 3. Component Table

| Component | Paper (s75,n31) | Tool ref (s75,n31) | Attack A (s66,n8) | Attack B (s66,n9) | Attack C (s66,n8+9) |
|-----------|:-:|:-:|:-:|:-:|:-:|
| C_biclique | 2^{0.74} | 2^{0.74} | 2^{0.74} | 2^{0.74} | 2^{0.74} |
| C_precomp | 2^{3.92} | 2^{3.92} | 2^{3.92} | 2^{3.92} | 2^{3.92} |
| C_recomp | 2^{7.01} | 2^{7.08} | 2^{6.99} | 2^{7.00} | 2^{7.03} |
| C_falpos | 2^{4.00} | 2^{4.00} | 2^{4.00} | 2^{4.00} | 2^{0.00} |
| raw_recomp | 1050 | 1097 | 1036 | 1040 | 1059 |
| state sboxes | 803 | 840 | 815 | 818 | 833 |
| key sboxes | 247 | 257 | 221 | 222 | 226 |
| \|v\| bits | 4 | 4 | 4 | 4 | 8 |
| Independent | yes | true | true | true | true |
| **Total** | **2^{255.34}** | **2^{255.39}** | **2^{255.32}** | **2^{255.33}** | **2^{255.21}** |
| Data | 2^{4} | 2^{4} | 2^{4} | 2^{4} | 2^{4} |

**Consistency checks:**
- C_biclique identical across all runs: PASS
- C_precomp identical across all runs: PASS
- C_falpos = 2^{4.00} for all single-nibble runs: PASS
- C_falpos = 2^{0.00} for Attack C (|v|=8, 2d=8): PASS
- Only C_recomp varies between runs, as expected: PASS

---

## 4. Genuine Improvement Assessment

### Attack A — State 66, Nibble 8

| Criterion | Threshold | Value | Status |
|-----------|-----------|-------|--------|
| raw_time < 2^{255.39} (beats tool ref) | 255.39 | 255.32 | PASS |
| raw_recomp < 1097 (fewer S-boxes than tool ref) | 1097 | 1036 | PASS |
| raw_recomp < 1050 (fewer than paper's precise count) | 1050 | 1036 | **PASS** |

**Verdict: Genuine improvement.** Attack A's raw_recomp of 1036 is 14 S-boxes
below the paper's precise count of 1050. No correction adjustment is needed to
establish this improvement — the tool itself counts fewer recomputation S-boxes
at this v position.

### Attack B — State 66, Nibble 9

| Criterion | Threshold | Value | Status |
|-----------|-----------|-------|--------|
| raw_time < 2^{255.39} | 255.39 | 255.33 | PASS |
| raw_recomp < 1097 | 1097 | 1040 | PASS |
| raw_recomp < 1050 | 1050 | 1040 | **PASS** |

**Verdict: Genuine improvement.** Attack B's raw_recomp of 1040 is 10 S-boxes
below the paper's precise count. Also improvement without correction.

### Attack C — State 66, Nibbles 8+9

| Criterion | Threshold | Value | Status |
|-----------|-----------|-------|--------|
| raw_time < 2^{255.39} | 255.39 | 255.21 | PASS |
| raw_recomp < 1097 | 1097 | 1059 | PASS |
| raw_recomp < 1050 | 1050 | 1059 | FAIL (1059 > 1050) |

Attack C has a raw_recomp of 1059, which is 9 above the paper's 1050 for the
single-nibble case. However, the raw_time of 2^{255.21} is dramatically lower
because the multi-nibble v eliminates C_falpos entirely (2^{0.00} vs 2^{4.00}).
The recomp increase of +23 S-boxes (from 1036 to 1059) adds approximately
+0.04 bits to C_recomp, while the C_falpos elimination saves approximately
-0.11 bits from the total. Net saving: ~0.07 bits.

The raw_recomp > 1050 criterion fails, so the recomp improvement claim requires
correction analysis. But the total time improvement is dominated by C_falpos,
not C_recomp, so the 2^{255.21} result is robust regardless of the S-box
correction methodology.

---

## 5. Correction Calibration Note

The known +47 S-box overcount was measured at the paper's v (state 75, nibble 31).
For state 66, nibble 8, the overcount will differ because:

- **Different state depth:** State 66 is 9 states (3 rounds) earlier than state
  75. The affectV backward propagation from state 66 covers rounds 22–30
  (9 rounds), while from state 75 it covers rounds 25–30 (6 rounds). More
  backward rounds means more opportunities for the union-of-all-values
  overestimate to accumulate. This suggests the overcount at state 66 may be
  **higher** than +47, not lower.

- **Different nibble position:** Nibble 8 is the first nibble of the third
  32-bit word (byte 4, high nibble). Nibble 31 is the last nibble of the
  fourth word (byte 15, low nibble). The Serpent linear transform's rotation
  and shift structure means different starting nibbles activate different
  diffusion paths. The net effect on overcount magnitude is difficult to
  predict without manual tracing.

- **Net expectation:** The increased backward depth likely makes the overcount
  at state 66 somewhat larger than +47. If so, the true recomp count at
  state 66 nibble 8 is even further below 1036 than the -47 adjustment
  suggests, strengthening the improvement claim.

A definitive correction would require comparing the tool's affectV output
against a manually traced propagation or the paper authors' tool. This is out
of scope. The raw_recomp comparison (1036 < 1050) is sufficient to establish
Attacks A and B as genuine improvements without relying on any correction.

---

## 6. Multi-Nibble Verdict

Attack C (nibbles 8+9, |v|=8 bits) produced the best result: **2^{255.21}**.

The C_falpos saving was decisive:
- C_recomp increased by +0.04 bits (2^{6.99} → 2^{7.03})
- C_falpos decreased by 4.00 bits (2^{4.00} → 2^{0.00})
- Net improvement: 0.11 bits in total time (2^{255.32} → 2^{255.21})

The C_recomp increase from adding nibble 9 was modest: only 23 additional
S-boxes (1036 → 1059), because nibbles 8 and 9 are adjacent in the same byte
and share much of the same diffusion path. This makes them an ideal pair for
multi-nibble v — minimal recomp increase, maximum C_falpos benefit.

Multi-nibble v is a productive direction. The next test would be a 3-nibble
or 4-nibble v at state 66, though diminishing returns are expected: each
additional nibble adds recomp S-boxes while C_falpos is already at 2^{0.00}
for |v| ≥ 2d = 8 bits. Beyond 2 nibbles, C_falpos cannot decrease further,
so only C_recomp matters — and it only increases.

---

## 7. Overall Verdict

The best attack found in this validation is **Attack C: state 66, nibbles 8+9,
with time complexity 2^{255.21} and data complexity 2^{4}**.

This matches the Menezes et al. (2020) best biclique result on Serpent-256
(2^{255.21}) while using the generator-set construction instead of the
traditional adjacent-key construction. It improves on the generator-set paper's
published 2^{255.34} by 0.13 bits.

The single-nibble Attack A (state 66, nibble 8) at 2^{255.32} also improves on
the paper's result, with raw_recomp = 1036 — 14 S-boxes below the paper's
precise count of 1050. This configuration improves on the published generator-set
attack without requiring any correction adjustment.

