# FIPS 180-4 SHA-256 Specifications — Complete Extract

I've compiled all the SHA-256 specific information from FIPS 180-4 and related standards documentation.
Here is the complete technical specification:

1. SHA-256 Functions (§4.1.2) — Logical Operations

The SHA-256 hash computation uses six 32-bit logical functions:

Choice Function:
- Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)

Majority Function:
- Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)

Upper-case Sigma Functions (compression loop):
- Σ₀(x) = ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)
- Σ₁(x) = ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)

Lower-case Sigma Functions (message schedule):
- σ₀(x) = ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)
- σ₁(x) = ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)

Where ROTR^n(x) is rightward bit rotation by n positions, and SHR^n(x) is rightward bit shift by n positions.

---
2. Round Constants (§4.2.2) — All 64 K Values

These are the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers:

K[0..15]:   428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
           d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174

K[16..31]:  e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
           983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967

K[32..47]:  27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
           a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070

K[48..63]:  19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
           748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2

---
3. Message Padding (§5.1.1) — Padding Rules

Let l = message length in bits.

The message M is padded by:
1. Appending a single bit 1 (represented as byte 0x80 at the start of the next byte)
2. Appending k zero bits, where k is the smallest non-negative solution to:
l + 1 + k ≡ 448 (mod 512)
2. Which is equivalent to: k = (447 - l) mod 512
3. Appending a 64-bit big-endian integer representing l (the original message length in bits)

Result: The padded message is a multiple of 512 bits. For a 24-bit message "abc", padding produces exactly one 512-bit block.

---
4. Initial Hash Values (§5.3.3) — H⁰[0..7]

These are the first 32 bits of the fractional parts of the square roots of the first eight prime numbers:

H⁰[0] = 0x6a09e667
H⁰[1] = 0xbb67ae85
H⁰[2] = 0x3c6ef372
H⁰[3] = 0xa54ff53a
H⁰[4] = 0x510e527f
H⁰[5] = 0x9b05688c
H⁰[6] = 0x1f83d9ab
H⁰[7] = 0x5be0cd19

---
5. SHA-256 Hash Computation (§6.2.2) — Complete Algorithm

Input: Message M, initial hash values H⁰[0..7]

Processing:

For each 512-bit message block (numbered 1 to N):

Step 1: Parse the 512-bit block into 16 32-bit big-endian words:
W[0..15] = M₀, M₁, ..., M₁₅   (as big-endian 32-bit words)

Step 2: Extend the message schedule to 64 words:
For t = 16 to 63:
 W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]

Step 3: Initialize working variables from previous block's hash:
a = H[0]    (or H⁽ⁱ⁻¹⁾[0] for blocks after the first)
b = H[1]    (or H⁽ⁱ⁻¹⁾[1])
c = H[2]
d = H[3]
e = H[4]
f = H[5]
g = H[6]
h = H[7]

Step 4: Main compression loop (64 rounds):
For t = 0 to 63:
 T1 = h + Σ₁(e) + Ch(e, f, g) + K[t] + W[t]
 T2 = Σ₀(a) + Maj(a, b, c)
 h = g
 g = f
 f = e
 e = d + T1
 d = c
 c = b
 b = a
 a = T1 + T2

Step 5: Update hash values (mod 2³²):
H[0] = a + H[0]
H[1] = b + H[1]
H[2] = c + H[2]
H[3] = d + H[3]
H[4] = e + H[4]
H[5] = f + H[5]
H[6] = g + H[6]
H[7] = h + H[7]

Output: After processing all N blocks, concatenate H[0..7] as big-endian bytes to produce the 256-bit hash.

---
6. Appendix B.1 — Worked Example for Message "abc"

Input Message:
"abc" = 0x61 0x62 0x63  (3 bytes = 24 bits)

After Padding (512-bit block):
0x61626380 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000018

The block ends with 0x00000018 = 24 bits (in big-endian), which is the original message length.

Message Schedule W[0..63]:

First 16 words (from the padded message block, parsed as big-endian):
W[0]  = 0x61626380    W[1]  = 0x00000000    W[2]  = 0x00000000    W[3]  = 0x00000000
W[4]  = 0x00000000    W[5]  = 0x00000000    W[6]  = 0x00000000    W[7]  = 0x00000000
W[8]  = 0x00000000    W[9]  = 0x00000000    W[10] = 0x00000000    W[11] = 0x00000000
W[12] = 0x00000000    W[13] = 0x00000000    W[14] = 0x00000000    W[15] = 0x00000018

Words W[16..63] are generated using the message schedule formula above. (The complete list is lengthy; shown is the process
for computing them.)

Initial Working Variables (equal to H⁰[0..7]):
a = 0x6a09e667
b = 0xbb67ae85
c = 0x3c6ef372
d = 0xa54ff53a
e = 0x510e527f
f = 0x9b05688c
g = 0x1f83d9ab
h = 0x5be0cd19

Final Hash After 64 Rounds:

The compression loop processes all 64 rounds, updating a, b, c, d, e, f, g, h and finally updating H[0..7]. The final 256-bit
SHA-256 hash for "abc" is:

H[0] = 0xba7816bf
H[1] = 0x8f01cfea
H[2] = 0x414140de
H[3] = 0x5dae2223
H[4] = 0xb00361a3
H[5] = 0x96177a9c
H[6] = 0xb410ff61
H[7] = 0xf20015ad

Canonical Hex Output:
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

---
Summary

This extract covers all six sections of FIPS 180-4 relevant to SHA-256:
- §4.1.2 — All six logical functions with exact rotation/shift constants
- §4.2.2 — Complete table of 64 round constants
- §5.1.1 — Message padding algorithm with the modular equation
- §5.3.3 — Initial hash values H⁰[0..7]
- §6.2.2 — Full hash computation algorithm with all steps
- Appendix B.1 — Worked example for "abc" with padded message, initial values, and final hash

Sources:
- https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf
- https://datatracker.ietf.org/doc/html/rfc6234
- https://www.cs.uaf.edu/2013/spring/cs463/lecture/02_20_SHA256.html
