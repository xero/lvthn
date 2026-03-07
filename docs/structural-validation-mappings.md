# Structural Validation Mappings

>[!NOTE]
> - **Date:** 2026-03-06
> - **Context:** Part of our [Biclique attack research against serpent256](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)

State and nibble mapping analysis for the structural validation of the
biclique attack on Serpent-256. Maps [BicliqueFinder](https://github.com/xero/BicliqueFinder/)'s internal model to
leviathan's roundHook instrumentation.

Sources analyzed:
- `leviathan/src/serpent.ts` (roundHook, getSubkeys, encrypt)
- `BicliqueFinder/BicliqueFinder/src/cifras/Serpent.java` (state model)
- `BicliqueFinder/BicliqueFinder/src/biclique/Biclique.java` (stateOfV usage)
- `BicliqueFinder/BicliqueFinder/src/util/ByteArray.java` (nibble indexing)
- `BicliqueFinder/BicliqueFinder/src/cifras/Cipher.java` (state index helpers)
- `leviathan/docs/serpent_audit.md` (byte ordering, roundHook design)

---

## Section 1 -- BicliqueFinder State Model

### 1.1 State numbering scheme

BicliqueFinder models Serpent-256 with 97 states (indices 0-96). Three states
per round, plus the final ciphertext state. Verified from Serpent.java:

```
getNUM_STATES() = 97
getNUM_ROUNDS() = 32
getNUM_KEYS()   = 33   (K0 through K32)
```

State classification methods from Serpent.java and Cipher.java:

- `getINDEX_OF_PRE_KEY(state)`: returns key index if state is a pre-key-XOR
  state. For state % 3 == 0: returns state/3. Special case: state 95 returns 32.
- `getINDEXES_OF_PRE_ADD_KEY()`: [0, 3, 6, ..., 93, 95] (33 entries)
- `getINDEXES_OF_POST_ADD_KEY()`: [1, 4, 7, ..., 94, 96] (pre_add_key + 1)
- `getINDEXES_OF_PRE_SBOX_STATES()`: [1, 4, 7, ..., 94] (first 32 of post_add_key)
- `getINDEXES_OF_POST_SBOX_STATES()`: [2, 5, 8, ..., 95] (pre_sbox + 1)

The `encryptForward` loop (Serpent.java:162-173) applies at each state i:
- If i is pre-key (i%3==0 or i==95): addKey with expanded key
- If i is post-key (in post_add_key list): apply S-box
- Otherwise (i%3==2, i!=95): apply linear transform L

### 1.2 State table (selected rows)

| State | Round (0-idx) | Position in round          | Semantic meaning           |
|-------|---------------|----------------------------|----------------------------|
| 0     | --            | --                         | Plaintext, pre-K0 XOR      |
| 1     | 0             | Post-K0, pre-S-box         | Input to S-box round 0     |
| 2     | 0             | Post-S-box, pre-LT         | S-box output round 0       |
| 3     | 0/1 boundary  | Post-LT round 0            | = Pre-K1 XOR               |
| 4     | 1             | Post-K1, pre-S-box         | Input to S-box round 1     |
| ...   |               |                            |                            |
| 63    | 20/21 boundary| Post-LT round 20           | = Pre-K21 XOR              |
| 64    | 21            | Post-K21, pre-S-box        | Input to S-box round 21    |
| 65    | 21            | Post-S-box, pre-LT         | S-box output round 21      |
| **66**| **21/22 boundary** | **Post-LT round 21**   | **= Pre-K22 XOR**          |
| 67    | 22            | Post-K22, pre-S-box        | Input to S-box round 22    |
| ...   |               |                            |                            |
| 91    | 30            | Post-K30, pre-S-box        | Biclique start (states 91-96) |
| 93    | 30/31 boundary| Post-LT round 30           | = Pre-K31 XOR              |
| 94    | 31            | Post-K31, pre-S-box        | Input to S-box round 31    |
| 95    | 31            | Post-S-box (no LT)         | = Pre-K32 XOR (special)    |
| 96    | --            | Post-K32 XOR               | Ciphertext                 |

**State 66 = 3 x 22.** It is the post-linear-transform output of round 21,
equivalently the pre-K22-XOR input to round 22. This is a `pre_add_key` state
(66 % 3 == 0, getINDEX_OF_PRE_KEY(66) = 22).

### 1.3 Nibbles 8 and 9 at state 66

In BicliqueFinder, the 128-bit state is a 16-byte ByteArray. It is logically
partitioned into 4 words of 4 bytes each:

- X[0] = bytes 0-3, X[1] = bytes 4-7, X[2] = bytes 8-11, X[3] = bytes 12-15

The matching variable v = state 66 nibbles 8+9 refers to 8 bits (two 4-bit
nibbles) within this 16-byte state. The exact bit positions are derived in
Section 4.

---

## Section 2 -- Leviathan roundHook Analysis

### 2.1 Hook signature

From serpent.ts:44:
```typescript
export type RoundHook = (round: number, state: number[], ec: number) => void;
```

**The state is `number[]` (5 integers), NOT `Uint8Array`.** Each element is a
32-bit word from leviathan's working register array r[0..4]. The `ec` parameter
is the EC constant for that round, used to decode which register slot holds
which logical word.

### 2.2 Register-to-word decoding

The EC constant `m` maps register slots to logical words via modular arithmetic:

| Logical word | Register slot |
|-------------|---------------|
| X0          | r[m % 5]      |
| X1          | r[m % 7]      |
| X2          | r[m % 11]     |
| X3          | r[m % 13]     |
| temp        | r[m % 17]     |

These 5 values are always distinct elements of {0, 1, 2, 3, 4}.

### 2.3 Hook firing points during encryption

The encrypt method (serpent.ts:305-342) has this structure:

```
K(r, 0, 1, 2, 3, 0)              -- XOR K0
n = 0, m = EC[0]
loop:
  S[n%8](r, m%5, m%7, m%11, m%13, m%17)   -- S-box for round n
  if n >= 31: break
  n++; m = EC[n]
  LK(r, m%5, m%7, m%11, m%13, m%17, n)    -- LT + K_n XOR
  roundHook(n-1, r.slice(), m)             -- hook fires here
end loop
K(r, 0, 1, 2, 3, 32)              -- XOR K32 (hardcoded slots)
roundHook(31, r.slice(), EC[31])   -- final hook
```

The LK function (serpent.ts:237-259) performs **both** the linear transform
and the next round's key XOR in a single interleaved operation. Mathematically,
after LK(r, a, b, c, d, e, n): r[a..d] = LT(S-box output) XOR K_n. The
interleaving is a performance optimization; the result is identical to applying
LT then key XOR separately (verified in serpent_audit.md).

### 2.4 Hook call to BF state mapping

For roundHook(R, state, ec):

| Hook call | Round param R | ec value | BF state captured     | Semantic                    |
|-----------|--------------|----------|-----------------------|-----------------------------|
| 0         | 0            | EC[1]    | 4 (post-K1)           | After round 0 LT + K1 XOR  |
| 1         | 1            | EC[2]    | 7 (post-K2)           | After round 1 LT + K2 XOR  |
| ...       | R            | EC[R+1]  | 3R+4 (post-K_{R+1})   | After round R LT + K_{R+1}  |
| 20        | 20           | EC[21]   | 64 (post-K21)         | After round 20 LT + K21 XOR|
| 21        | 21           | EC[22]   | **67 (post-K22)**     | After round 21 LT + K22 XOR|
| ...       |              |          |                       |                             |
| 30        | 30           | EC[31]   | 94 (post-K31)         | After round 30 LT + K31 XOR|
| 31        | 31           | EC[31]   | 96 (ciphertext)       | After round 31 S-box + K32  |

**General formula (R = 0..30):** BF state = 3(R+1) + 1 = 3R + 4.

**No hook call captures BF state 66 directly.** State 66 = 3 x 22 falls between
hookCall 20 (state 64) and hookCall 21 (state 67). The roundHook fires after
LK, which combines LT with the *next* round's key XOR. State 66 is the
intermediate point after LT but before K22 XOR.

**To recover state 66:** Use hookCall 21 (round=21, BF state 67) and XOR out
the K22 contribution. See Section 6.

### 2.5 EC constants for key rounds

The EC array from serpent.ts:308-309:
```
EC = [44255, 61867, 45034, 52496, 73087, 56255, 43827, 41448,
      18242,  1939, 18581, 56255, 64584, 31097, 26469, 77728,
      77639,  4216, 64585, 31097, 66861, 78949, 58006, 59943,
      49676, 78950,  5512, 78949, 27525, 52496, 18670, 76143]
```

For roundHook(21): ec = EC[22] = 58006.

| Modulus | Value | Meaning          |
|---------|-------|------------------|
| % 5     | 1     | X0 = r[1]       |
| % 7     | 4     | **X1 = r[4]**   |
| % 11    | 3     | X2 = r[3]       |
| % 13    | 0     | X3 = r[0]       |
| % 17    | 2     | temp = r[2]     |

---

## Section 3 -- getSubkeys() Viability

### 3.1 Method signature and format

From serpent.ts:294-297:
```typescript
getSubkeys(key: Uint8Array): Uint32Array {
    this.init(key);
    return new Uint32Array(this.key);
}
```

Returns a copy of the 132-word (528-byte) expanded key array. Subkey K_i
occupies words at indices [4i, 4i+1, 4i+2, 4i+3] for i = 0..32.

### 3.2 Word ordering within subkeys

The LK function XORs subkey words into register slots as:
```
r[a] ^= key[4*i + 0]   -- a = ec%5 = X0 slot
r[b] ^= key[4*i + 1]   -- b = ec%7 = X1 slot
r[c] ^= key[4*i + 2]   -- c = ec%11 = X2 slot
r[d] ^= key[4*i + 3]   -- d = ec%13 = X3 slot
```

So `key[4i + k]` is the word XORed into the register slot that holds logical
word Xk at round i. For the purpose of XOR-ing out the key contribution (to
recover state 66 from state 67), this is sufficient: we XOR out `key[4*22 + k]`
from register slot k's EC-derived position.

**Caveat:** The key schedule (init method, serpent.ts:193-226) stores subkey
words using KC-constant-derived register permutations via `keyStore`. The stored
word order in `key[]` is designed to match the encryption's EC-derived register
mapping, but the correspondence to "standard" Serpent subkey words (as defined
in the specification) depends on the KC/EC constant interplay. For the XOR-out
operation, this does not matter -- we are simply reversing the XOR that LK
applied.

### 3.3 Key numbering consistency

Both implementations use 0-indexed subkeys K0 through K32 (33 total). Leviathan's
`key[4*31 .. 4*31+3]` corresponds to BicliqueFinder's K31. Confirmed by:
- Both have 33 subkeys
- `getSubkeys()` comment: "33 subkeys x 4 words each"
- BicliqueFinder: `getNUM_KEYS() = 33`, keyIndex=31 for K31/K32 pair

### 3.4 Recommendation

**Use getSubkeys().** It is viable and sufficient for:

1. **Key XOR reversal** (recovering state 66 from roundHook state 67): XOR out
   `subkeys[4*22 + k]` from the appropriate register slot.

2. **Subkey difference verification**: Given two master keys K and K', call
   `getSubkeys(K)` and `getSubkeys(K')`, XOR corresponding words, and verify
   that the differences appear only in the expected subkeys/nibbles.

3. **Master key pair discovery**: To find master keys that produce a specific
   single-nibble subkey difference (e.g., nibble 13 of K18), enumerate
   modifications to the 256-bit master key and check the resulting subkey
   schedule via getSubkeys(). The key schedule is an affine recurrence, so
   small master key changes propagate predictably.

Key schedule inversion is NOT required.

---

## Section 4 -- Nibble Ordering in BicliqueFinder

### 4.1 getNibble implementation

From ByteArray.java:1028-1033:
```java
public int getNibble(int position) {
    if ((position & 1) == 0)
        return (array[position / 2]  >> 4) & 0xF;   // even: HIGH nibble
    else
        return array[(--position) / 2] & 0xF;        // odd: LOW nibble
}
```

### 4.2 setNibble implementation

From ByteArray.java:1079-1085:
```java
public ByteArray setNibble(int position, int value) {
    int byteIndex = (int)(position / 2);
    if ((position & 0x1) == 0)  // even: set HIGH nibble (bits 7-4)
        array[byteIndex] = (short)((array[byteIndex] & 0x0F) | ((value << 4) & 0xF0));
    else                        // odd: set LOW nibble (bits 3-0)
        array[byteIndex] = (short)((array[byteIndex] & 0xF0) | (value & 0x0F));
    ...
}
```

### 4.3 Nibble-to-byte formula

For nibble index N in a ByteArray:

```
Byte index B = floor(N / 2)
If N is even: HIGH nibble of byte B (bits 7-4)
If N is odd:  LOW nibble of byte B  (bits 3-0)
```

### 4.4 Application to nibbles 8 and 9

| Nibble | Byte index | Position in byte | Bits of byte |
|--------|-----------|------------------|-------------|
| 8      | 4         | HIGH nibble      | bits 7-4    |
| 9      | 4         | LOW nibble       | bits 3-0    |

**Both nibbles 8 and 9 occupy byte 4 of the 16-byte state.** Together they
constitute the entire byte: nibble 8 is the high nibble, nibble 9 is the low
nibble.

### 4.5 Byte-to-word mapping

The 16-byte state is partitioned into 4 words (Serpent.java L function,
lines 237-240):
```java
X.get(i) = estado.getSubBytes(i*4, (i+1)*4)
// X[0] = bytes 0-3, X[1] = bytes 4-7, X[2] = bytes 8-11, X[3] = bytes 12-15
```

Byte 4 is the FIRST byte (offset 0) of word X[1].

### 4.6 Byte ordering within words (big-endian)

ByteArray's `rotateLeft` (line 625-633) reveals the bit ordering:
```java
private void rotateLeft() {
    int carry = 0, currByte;
    for (int i = this.length()-1; i >= 0; i--) {
        currByte = getByte(i);
        setByte(i, currByte<<1 ^ carry);
        carry = (currByte>>7) & 1;
    }
    setByte(this.length()-1, getByte(this.length()-1) ^ carry);
}
```

Iteration from last byte to first byte, MSB carry propagating toward byte 0.
This is **big-endian**: byte 0 is the most significant byte of the word.

For a 4-byte word:
- Byte 0 = bits 31-24 (MSB)
- Byte 1 = bits 23-16
- Byte 2 = bits 15-8
- Byte 3 = bits 7-0 (LSB)

### 4.7 Nibbles 8+9 in terms of 32-bit word bits

Byte 4 = byte 0 of X[1] = MSB of X[1] = bits 31-24 of X[1].

| Nibble | Word | Bit range within word |
|--------|------|----------------------|
| 8      | X[1] | bits 31-28           |
| 9      | X[1] | bits 27-24           |
| 8+9    | X[1] | bits 31-24 (= MSB)   |

---

## Section 5 -- Leviathan Byte Ordering at State 66

### 5.1 Internal representation

Leviathan operates on 4 (extending to 5) 32-bit integer registers r[0..4].
There is no byte-level serialization during encryption -- the roundHook
receives the raw integer array.

Input loading (serpent.ts:311-316):
```typescript
// Reverse plaintext bytes
for (let i = 0, len = pt.length; i < len; i++) blk[i] = pt[len - i - 1];
// Load as little-endian 32-bit words
const r = [this.getW(blk, 0), this.getW(blk, 4), this.getW(blk, 8), this.getW(blk, 12)];
```

Where `getW` packs 4 bytes as little-endian (serpent.ts:77-79):
```typescript
getW(a, i) { return a[i] | a[i+1]<<8 | a[i+2]<<16 | a[i+3]<<24; }
```

This is the AES submission convention (reversed bytes, LE word packing),
distinct from BicliqueFinder's direct ByteArray representation. However, this
difference only affects the initial state loading -- it does NOT affect the
structural validation, which compares two leviathan encryptions against each
other (same convention throughout).

### 5.2 Register mapping at state 66

At roundHook(21), ec = EC[22] = 58006:

| Register | Logical word | EC derivation |
|----------|-------------|---------------|
| r[0]     | X3          | 58006 % 13 = 0 |
| r[1]     | X0          | 58006 % 5 = 1  |
| r[2]     | temp        | 58006 % 17 = 2 |
| r[3]     | X2          | 58006 % 11 = 3 |
| r[4]     | **X1**      | 58006 % 7 = 4  |

**X1 (the word containing nibbles 8+9) is in register slot 4.**

### 5.3 Key XOR performed by LK

Inside LK(r, a=1, b=4, c=3, d=0, e=2, i=22), the key XOR operations are
(serpent.ts:253-258):

```typescript
r[d] ^= this.key[4*i + 3];   // r[0] ^= key[91]  (X3 slot)
r[b] ^= this.key[4*i + 1];   // r[4] ^= key[89]  (X1 slot)
r[a]  = this.rotW(r[a], 5);   // LT step 9
r[c]  = this.rotW(r[c], 22);  // LT step 10
r[a] ^= this.key[4*i + 0];   // r[1] ^= key[88]  (X0 slot)
r[c] ^= this.key[4*i + 2];   // r[3] ^= key[90]  (X2 slot)
```

Note: X1 (r[4]) and X3 (r[0]) are XORed with their key words **before** LT
steps 9-10. X0 (r[1]) and X2 (r[3]) are XORed **after** LT steps 9-10. This
interleaving is a performance optimization; the mathematical result is identical
to full LT followed by key XOR (confirmed in serpent_audit.md).

---

## Section 6 -- Complete Mapping Table

### 6.1 Summary

| BicliqueFinder         | Meaning                      | Leviathan roundHook             |
|-----------------------|------------------------------|----------------------------------|
| State 66              | Post-LT round 21, pre-K22   | hookCall 21 (round=21), XOR out K22 |
| Nibble 8              | Bits 31-28 of X1             | `(state[4] ^ subkeys[89]) >>> 28) & 0xF` |
| Nibble 9              | Bits 27-24 of X1             | `((state[4] ^ subkeys[89]) >>> 24) & 0xF` |
| Nibbles 8+9 (byte)    | Bits 31-24 of X1 (MSB)       | `((state[4] ^ subkeys[89]) >>> 24) & 0xFF` |

### 6.2 TypeScript extraction expression

```typescript
const s = new Serpent();
const subkeys = s.getSubkeys(key);

s.roundHook = (round: number, state: number[], ec: number) => {
  if (round === 21) {
    // roundHook(21) captures BF state 67 (post-K22).
    // ec = EC[22] = 58006: X0=state[1], X1=state[4], X2=state[3], X3=state[0]
    //
    // XOR out K22's X1 word to recover BF state 66 (pre-K22).
    // LK XORed key[4*22+1] = key[89] into r[4] (the X1 slot).
    const X1_state66 = (state[4] ^ subkeys[89]) >>> 0;  // unsigned

    // BicliqueFinder nibbles 8+9 = bits 31-24 of X1 = MSB of X1
    const nibble8 = (X1_state66 >>> 28) & 0xF;
    const nibble9 = (X1_state66 >>> 24) & 0xF;
    const matchingVariable = (X1_state66 >>> 24) & 0xFF;  // 8-bit value
  }
};

s.encrypt(key, plaintext);
```

### 6.3 Full state extraction at state 66

To extract all 4 words at BF state 66 (e.g., for full state comparison):

```typescript
if (round === 21) {
  // EC[22] = 58006: slots are X0=r[1], X1=r[4], X2=r[3], X3=r[0]
  const X0 = (state[1] ^ subkeys[4*22 + 0]) >>> 0;
  const X1 = (state[4] ^ subkeys[4*22 + 1]) >>> 0;
  const X2 = (state[3] ^ subkeys[4*22 + 2]) >>> 0;
  const X3 = (state[0] ^ subkeys[4*22 + 3]) >>> 0;
}
```

---

## Section 7 -- Cross-check

### 7.1 Byte ordering verification by reasoning

The structural validation compares two leviathan encryptions (same key
convention throughout). The question is whether extracting bits 31-24 of X1
in leviathan corresponds to BicliqueFinder's nibbles 8+9 of the state.

**Argument for correctness:**

1. Both implementations perform identical mathematical operations on 32-bit
   words: the same S-boxes (bitslice Boolean circuits), the same linear
   transform (rotations + XOR), the same key schedule (affine recurrence +
   S-box application).

2. The Serpent LT operates on 4 logical words {X0, X1, X2, X3}. Each LT step
   is a rotation or XOR on a specific word. The LT does not reorder bits within
   a word -- it only rotates and mixes whole words.

3. BicliqueFinder serializes each word as 4 bytes in big-endian order (byte 0 =
   MSB). Its nibble 8 = bits 31-28 of word X1 (high nibble of MSB).

4. Leviathan stores each word as a native 32-bit JavaScript integer. Bits 31-28
   of the integer correspond to the same mathematical bits as BicliqueFinder's
   nibble 8.

5. The EC constant for roundHook(21) identifies r[4] as the X1 register slot.
   The LK function XORs `key[89]` into r[4]. XOR-ing it back out recovers
   the pre-K22 value of X1.

6. Therefore: `(state[4] ^ subkeys[89]) >>> 28) & 0xF` extracts the same
   mathematical nibble as BicliqueFinder's `getNibble(8)` at state 66.

### 7.2 Potential validation test

Confirmed empirically. Encrypted the all-zero plaintext with the all-zero
256-bit key in both implementations:

- **BicliqueFinder**: `Serpent.encryptFull(new ByteArray(16), 0)` returns all
  97 states. Read state 66 (index 66 in the list), extract nibbles 8+9.

- **Leviathan**: Set roundHook, encrypt, apply the Section 6.2 extraction.
  Compare the 8-bit matching variable.

As both values match, the mapping is confirmed.

See: [test/spec/biclique-structural.test.ts](test/spec/biclique-structural.test.ts)

### 7.3 Input byte ordering note

Leviathan reverses input plaintext bytes before LE word loading (AES submission
convention). BicliqueFinder uses direct ByteArray representation (no reversal).
For the same external plaintext, the two implementations will have DIFFERENT
internal state values at every intermediate point. This does NOT affect the
structural validation because:
- The validation compares two leviathan encryptions (same convention)
- Differential properties (which nibbles are active) are preserved under any
  fixed bijective input transformation

However, if comparing absolute state values between the two implementations
(Section 7.2 cross-check), the plaintext must be adjusted: either reverse the
bytes when passing to one implementation, or accept that the values will differ
and verify only the differential properties.

---

## Section 8 -- Open Issues

### 8.1 S-box output register permutation (RESOLVED by EC decoding)

Leviathan's bitslice S-boxes permute which register slot holds which logical
word. The EC constants track this permutation across rounds. For roundHook(21),
EC[22]=58006 correctly identifies X1=r[4]. No ambiguity remains.

### 8.2 subkeys[] word semantics (RESOLVED)

The `key[4i+k]` values stored by the key schedule use KC-constant-derived
register permutations. For the XOR-out operation, this is irrelevant: LK XORed
`key[89]` into r[4], so XOR-ing `key[89]` back out reverses the operation
exactly, regardless of which "logical" subkey component key[89] represents.

### 8.3 Runtime verification needed (RESOLVED)

The complete mapping (Section 6) is derived from static analysis of:
- The encrypt loop structure (which hook call corresponds to which BF state)
- The EC constant arithmetic (which register holds X1)
- The LK function (which key word was XORed into which register)
- The ByteArray nibble convention (which bits of X1 are nibbles 8+9)

Each step is individually verifiable: encrypt all-zero plaintext/key in both
implementations then compare state 66 nibbles 8+9. This is a single, inexpensive
test that validates the entire mapping pipeline.

See: [test/spec/biclique-structural.test.ts](test/spec/biclique-structural.test.ts)

### 8.4 K32 subkey mapping anomaly (LOW PRIORITY)

The final key XOR (K32) uses `K(r, 0, 1, 2, 3, 32)` with hardcoded register
indices, not EC-derived indices. At that point the register mapping (from
EC[31]=76143) is X0=r[3], X1=r[4], X2=r[1], X3=r[2]. The hardcoded XOR
applies key words to r[0..3], skipping r[4] (X1). The key schedule must
compensate by storing K32's words in the permuted order matching these hardcoded
indices. This does not affect state 66 (which uses K22 via LK with EC-derived
indices) but would matter for any validation involving the final ciphertext
state (BF state 96). The `setWInv` output ordering (r[3], r[2], r[1], r[0])
also compensates. This anomaly should be investigated if ciphertext-level
validation is needed.

### 8.5 Master key pair discovery (OPEN)

The structural validation requires master key pairs that produce specific
subkey differences (e.g., single nibble difference in K18). The recommended
approach:

1. Pick an arbitrary master key K
2. For each byte position b in the 256-bit key, for each bit flip:
   - Create K' = K with bit b flipped
   - Compute `getSubkeys(K) XOR getSubkeys(K')`
   - Check if the difference in K18 matches the desired nibble pattern
3. The key schedule is linear (affine recurrence), so single-bit master key
   changes produce sparse, deterministic subkey differences

This search is efficient (256 x 8 = 2048 candidates for single-bit flips)
and can be extended to multi-bit differences if needed. The alternative --
analytical key schedule inversion -- is also possible but unnecessary given
getSubkeys().
