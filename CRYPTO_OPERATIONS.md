# CRYPTOGRAPHIC OPERATIONS REFERENCE — BTP HSM on Keystone TEE

**Purpose:** Understand every cryptographic primitive implemented in the HSM enclave — the theory, the mathematics, the implementation, and the exact test vectors used on the server.

---

## TABLE OF CONTENTS

1. [AES-256 (Advanced Encryption Standard)](#1-aes-256-advanced-encryption-standard)
2. [AES-CBC Mode with PKCS#7 Padding](#2-aes-cbc-mode-with-pkcs7-padding)
3. [SHA-256 (Secure Hash Algorithm)](#3-sha-256-secure-hash-algorithm)
4. [HMAC-SHA256 (Hash-based Message Authentication Code)](#4-hmac-sha256-hash-based-message-authentication-code)
5. [PRNG (Pseudorandom Number Generator)](#5-prng-pseudorandom-number-generator)
6. [Key Store & Handle Management](#6-key-store--handle-management)
7. [Test Case Mapping — What Each Test Actually Exercises](#7-test-case-mapping--what-each-test-actually-exercises)
8. [Appendix: Galois Field GF(2⁸) Arithmetic](#appendix-galois-field-gf2⁸-arithmetic-for-aes)

---

## 1. AES-256 (Advanced Encryption Standard)

### 1.1 What Is It?

AES (FIPS PUB 197) is a **symmetric block cipher** — the same secret key is used for both encryption and decryption. It operates on fixed 16-byte (128-bit) blocks.

- **AES-128**: 128-bit key → 10 rounds
- **AES-256**: 256-bit key → **14 rounds** ← (what we use)

AES is the worldwide standard for encrypting data at rest and in transit (used in TLS, disk encryption, Wi-Fi WPA2, etc.).

### 1.2 The State Matrix

AES treats each 16-byte input block as a 4×4 matrix of bytes called the **State**, filled column by column:

```
Input bytes:  b0  b1  b2  b3  b4  b5  b6  b7  b8  b9  b10 b11 b12 b13 b14 b15

State matrix:
    +------+------+------+------+
    |  b0  |  b4  |  b8  |  b12 |   <-- Row 0
    |  b1  |  b5  |  b9  |  b13 |   <-- Row 1
    |  b2  |  b6  |  b10 |  b14 |   <-- Row 2
    |  b3  |  b7  |  b11 |  b15 |   <-- Row 3
    +------+------+------+------+
      Col 0  Col 1  Col 2  Col 3
```

This is the code in `crypto_aes.c:106-110`:
```c
for (int r = 0; r < 4; r++)
    for (int c = 0; c < 4; c++)
        state[r][c] = in[r + 4 * c];  // column-major fill
```

### 1.3 The Four Round Operations

Each AES round applies 4 transformations to the State:

#### (a) SubBytes — Non-linear byte substitution

Every byte `b` in the State is replaced with `S-box[b]`. The S-box is a 256-entry lookup table derived from:

1. Compute the **multiplicative inverse** of `b` in the Galois Field GF(2⁸), where the irreducible polynomial is `x⁸ + x⁴ + x³ + x + 1` (= `0x11B`). By convention, `0⁻¹ = 0`.
2. Apply an **affine transformation** over GF(2):

```
b'ᵢ = bᵢ ⊕ b₍ᵢ₊₄₎mod₈ ⊕ b₍ᵢ₊₅₎mod₈ ⊕ b₍ᵢ₊₆₎mod₈ ⊕ b₍ᵢ₊₇₎mod₈ ⊕ cᵢ
```

where `c = 0x63 = 01100011₂`.

**Example:** Byte `0x53` → S-box lookup → `0xED`

In our code (`crypto_aes.c:123-125`):
```c
for (int r = 0; r < 4; r++)
    for (int c = 0; c < 4; c++)
        state[r][c] = sbox[state[r][c]];
```

For decryption, **InvSubBytes** uses the inverse S-box (`rsbox[]` in `crypto_aes.c:23-40`).

#### (b) ShiftRows — Cyclic row rotation

Each row is shifted left by its row index:
- Row 0: no shift
- Row 1: shift left by 1
- Row 2: shift left by 2
- Row 3: shift left by 3

```
Before:                    After:
+----+----+----+----+      +----+----+----+----+
| a0 | a1 | a2 | a3 | R0  | a0 | a1 | a2 | a3 |  (no shift)
+----+----+----+----+      +----+----+----+----+
| b0 | b1 | b2 | b3 | R1  | b1 | b2 | b3 | b0 |  (shift 1 left)
+----+----+----+----+      +----+----+----+----+
| c0 | c1 | c2 | c3 | R2  | c2 | c3 | c0 | c1 |  (shift 2 left)
+----+----+----+----+      +----+----+----+----+
| d0 | d1 | d2 | d3 | R3  | d3 | d0 | d1 | d2 |  (shift 3 left)
+----+----+----+----+      +----+----+----+----+
```

In our code (`crypto_aes.c:128-132`):
```c
// Row 1: shift left by 1
t = state[1][0]; state[1][0]=state[1][1]; state[1][1]=state[1][2]; state[1][2]=state[1][3]; state[1][3]=t;
// Row 2: shift left by 2
t = state[2][0]; state[2][0]=state[2][2]; state[2][2]=t;
t = state[2][1]; state[2][1]=state[2][3]; state[2][3]=t;
// Row 3: shift left by 3 = shift right by 1
t = state[3][3]; state[3][3]=state[3][2]; state[3][2]=state[3][1]; state[3][1]=state[3][0]; state[3][0]=t;
```

For decryption, **InvShiftRows** shifts in the opposite direction.

#### (c) MixColumns — Column-wise linear mixing

Each column is multiplied by a fixed matrix in GF(2⁸):

```
| s'0 |     | 2  3  1  1 |     | s0 |
| s'1 |  =  | 1  2  3  1 |  x  | s1 |    (all arithmetic in GF(2^8))
| s'2 |     | 1  1  2  3 |     | s2 |
| s'3 |     | 3  1  1  2 |     | s3 |
```

The key operation is **`xtime(x)`** — multiplication by 2 in GF(2⁸):
```
xtime(x) = (x << 1) ⊕ (0x1B if bit 7 of x was 1, else 0x00)
```

And multiplication by 3: `3 × x = 2 × x ⊕ x = xtime(x) ⊕ x`

The formula expands to:
```
s'₀ = (2·s₀) ⊕ (3·s₁) ⊕ s₂ ⊕ s₃
s'₁ = s₀ ⊕ (2·s₁) ⊕ (3·s₂) ⊕ s₃
s'₂ = s₀ ⊕ s₁ ⊕ (2·s₂) ⊕ (3·s₃)
s'₃ = (3·s₀) ⊕ s₁ ⊕ s₂ ⊕ (2·s₃)
```

Our code uses an equivalent formulation (`crypto_aes.c:135-141`):
```c
// Uses identity: 2·a ⊕ 3·b = xtime(a ⊕ b) ⊕ b
state[0][c] = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;  // 2·a0 ⊕ 3·a1 ⊕ a2 ⊕ a3
state[1][c] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;  // a0 ⊕ 2·a1 ⊕ 3·a2 ⊕ a3
state[2][c] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;  // a0 ⊕ a1 ⊕ 2·a2 ⊕ 3·a3
state[3][c] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;  // 3·a0 ⊕ a1 ⊕ a2 ⊕ 2·a3
```

For decryption, **InvMixColumns** uses the inverse matrix with coefficients {0x0E, 0x0B, 0x0D, 0x09} (`crypto_aes.c:219-224`).

**MixColumns is NOT applied in the final (14th) round** — this is per the AES specification.

#### (d) AddRoundKey — XOR with round key

Each column of the State is XORed with a 32-bit word from the expanded round key schedule:

```
State[col] = State[col] ⊕ RoundKey[round × 4 + col]
```

### 1.4 Key Expansion (Key Schedule)

AES-256 expands the 256-bit (8 words, Nk=8) key into 60 words (for 14 rounds + initial):

```
For i = 0..7:   W[i] = Key word i                    (copy the key)
For i = 8..59:
    temp = W[i-1]
    if (i mod 8 == 0):
        temp = SubWord(RotWord(temp)) ⊕ Rcon[i/8]    (rotate, substitute, XOR constant)
    else if (i mod 8 == 4):
        temp = SubWord(temp)                          (extra substitution for AES-256 only)
    W[i] = W[i-8] ⊕ temp
```

Where:
- `RotWord([a₀, a₁, a₂, a₃])` = `[a₁, a₂, a₃, a₀]` (left rotate by 1 byte)
- `SubWord` applies the S-box to each of the 4 bytes
- `Rcon[i]` = `[xⁱ⁻¹, 0, 0, 0]` in GF(2⁸): `{01, 02, 04, 08, 10, 20, 40, 80, 1B, 36}`

This is `crypto_aes.c:72-101`.

### 1.5 Complete AES-256 Encryption Flow

```
                    Input Block (16 bytes)
                            |
                 +----------v-----------+
                 |   AddRoundKey (0)    |  <-- Round Key 0
                 +----------+-----------+
                            |
            +---------------v----------------+
            |       REPEAT 13 TIMES          |  <-- Rounds 1 to 13
            |  +-------------------------+   |
            |  | 1. SubBytes             |   |
            |  | 2. ShiftRows            |   |
            |  | 3. MixColumns           |   |
            |  | 4. AddRoundKey (i)      |   |
            |  +-------------------------+   |
            +---------------+----------------+
                            |
                 +----------v-----------+
                 |   Final Round (14)   |
                 |   1. SubBytes        |
                 |   2. ShiftRows       |
                 |   3. AddRoundKey     |  <-- NO MixColumns
                 +----------+-----------+
                            |
                    Output Block (16 bytes)
```

---

## 2. AES-CBC MODE WITH PKCS#7 PADDING

### 2.1 Why CBC? (Cipher Block Chaining)

Raw AES encrypts one 16-byte block at a time (ECB mode). ECB is insecure because identical plaintext blocks produce identical ciphertext blocks (leaks patterns). **CBC** chains blocks together using an Initialization Vector (IV):

```
C₀ = AES_Encrypt(P₀ ⊕ IV)
C₁ = AES_Encrypt(P₁ ⊕ C₀)
C₂ = AES_Encrypt(P₂ ⊕ C₁)
...
Cₙ = AES_Encrypt(Pₙ ⊕ Cₙ₋₁)
```

Decryption reverses:
```
P₀ = AES_Decrypt(C₀) ⊕ IV
P₁ = AES_Decrypt(C₁) ⊕ C₀
...
Pₙ = AES_Decrypt(Cₙ) ⊕ Cₙ₋₁
```

### 2.2 CBC Diagram

```
Encryption:

  IV ---+
        |
        v
  P0 --XOR-- AES_Enc ----> C0 ---+
                                  |
                                  v
                    P1 ---XOR-- AES_Enc ----> C1 ---+
                                                    |
                                                    v
                                      P2 ---XOR-- AES_Enc ----> C2 --> ...

Decryption:

  IV ---------------+
                    |
                    v
  C0 -- AES_Dec --XOR----> P0
  |
  +---------------------+
                        |
                        v
  C1 -- AES_Dec ------XOR----> P1
```

### 2.3 PKCS#7 Padding

If the message is not a multiple of 16 bytes, pad it. PKCS#7 rule: append `N` bytes, each with the value `N`:

| Message Length | Padding Needed (N) | Padding Bytes |
|---------------|--------------------:|---------------|
| 15 bytes | 1 | `01` |
| 14 bytes | 2 | `02 02` |
| 13 bytes | 3 | `03 03 03` |
| ... | ... | ... |
| 1 byte | 15 | `0F 0F 0F ... 0F` (×15) |
| 16 bytes | 16 | `10 10 10 ... 10` (×16) — full block of padding |

If the message is already 16 bytes, you **still add 16 bytes of padding** — this ensures padding is always unambiguous.

### 2.4 Exact Test Vector Used on the Server (Tests 1–3)

**Test 2: AES-256 CBC Encryption**

```
Key:        256 bits, randomly generated inside enclave (handle 0x1001)
            (raw bytes never leave enclave memory)

IV:         00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF

Plaintext:  "IIT-Kgp Keystone Enclave HSM Protected Top Secret 2026!"
            = 55 bytes of ASCII

Padding:    55 mod 16 = 7 remaining → pad with 9 bytes of value 0x09
            Total: 55 + 9 = 64 bytes = 4 AES blocks

Ciphertext: f9 da 89 a1 57 47 6e 8d 04 5d 43 46 03 d5 6c 54
            70 a2 98 06 cd c4 37 ad ac d7 a8 f1 2b 85 6b 0a
            5d 2c 5d 02 f3 f5 25 8d e0 3c e7 a7 ea 56 9e cf
            78 c2 e0 7b ad 7a b2 aa d7 09 39 90 8f 20 c5 ca
            = 64 bytes
```

**Test 3: AES-256 CBC Decryption**
```
Input:      The 64-byte ciphertext from Test 2
Same IV:    00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
Same Key:   Handle 0x1001 (same key slot inside enclave)

Output:     "IIT-Kgp Keystone Enclave HSM Protected Top Secret 2026!"
            = 55 bytes (PKCS#7 padding stripped)

Verification: memcmp(decrypted, original_plaintext) == 0 → PASS
```

The IV is defined in `hsm_host.cpp:23-24`:
```c
static uint8_t g_aes_iv[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
```

---

## 3. SHA-256 (SECURE HASH ALGORITHM)

### 3.1 What Is It?

SHA-256 (FIPS 180-4) is a **cryptographic hash function** that maps arbitrary-length input to a fixed **256-bit (32-byte)** digest. Properties:

1. **Deterministic** — Same input always gives same hash.
2. **One-way** — Cannot reverse the hash to recover the input.
3. **Collision-resistant** — Infeasible to find two different inputs with the same hash.
4. **Avalanche effect** — Changing 1 bit of input changes ~50% of output bits.

### 3.2 SHA-256 Algorithm Step by Step

#### Step 1: Preprocessing

1. **Append bit `1`** to the message: add byte `0x80`.
2. **Append zeros** until message length ≡ 448 mod 512 (56 mod 64 in bytes).
3. **Append original message length** as a 64-bit big-endian integer.

Result: message is now a multiple of 512 bits (64 bytes).

#### Step 2: Initialize Hash Values

Eight 32-bit words, derived from the fractional parts of the square roots of the first 8 primes:

```
H₀ = 0x6a09e667    (√2)
H₁ = 0xbb67ae85    (√3)
H₂ = 0x3c6ef372    (√5)
H₃ = 0xa54ff53a    (√7)
H₄ = 0x510e527f    (√11)
H₅ = 0x9b05688c    (√13)
H₆ = 0x1f83d9ab    (√17)
H₇ = 0x5be0cd19    (√19)
```

This is `crypto_sha256.c:55-63`.

#### Step 3: Round Constants K[0..63]

64 constants derived from the fractional parts of the cube roots of the first 64 primes:

```
K[0]  = 0x428a2f98    K[1]  = 0x71374491    K[2]  = 0xb5c0fbcf   ...
K[62] = 0xbef9a3f7    K[63] = 0xc67178f2
```

This is `crypto_sha256.c:4-13`.

#### Step 4: Process Each 512-bit Block

For each 64-byte block of the padded message:

**a) Prepare Message Schedule W[0..63]:**

```
W[t] = M[t]                                          for t = 0..15   (copy 16 words from block)
W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]  for t = 16..63 (expand)
```

Where the lower-case sigma functions are:
```
σ₀(x) = ROTR₇(x) ⊕ ROTR₁₈(x) ⊕ SHR₃(x)
σ₁(x) = ROTR₁₇(x) ⊕ ROTR₁₉(x) ⊕ SHR₁₀(x)
```

**b) Initialize Working Variables:**
```
a = H₀,  b = H₁,  c = H₂,  d = H₃
e = H₄,  f = H₅,  g = H₆,  h = H₇
```

**c) 64 Compression Rounds:**

For each round `t = 0..63`:
```
T₁ = h + Σ₁(e) + Ch(e, f, g) + K[t] + W[t]
T₂ = Σ₀(a) + Maj(a, b, c)

h = g
g = f
f = e
e = d + T₁
d = c
c = b
b = a
a = T₁ + T₂
```

Where the upper-case Sigma and logical functions are:
```
Σ₀(a) = ROTR₂(a) ⊕ ROTR₁₃(a) ⊕ ROTR₂₂(a)
Σ₁(e) = ROTR₆(e) ⊕ ROTR₁₁(e) ⊕ ROTR₂₅(e)
Ch(e, f, g)  = (e AND f) ⊕ (NOT e AND g)        "Choose": e picks from f or g
Maj(a, b, c) = (a AND b) ⊕ (a AND c) ⊕ (b AND c) "Majority": majority vote
```

All arithmetic is modular addition mod 2³².

This is `crypto_sha256.c:23-53`.

**d) Update Hash Values:**
```
H₀ += a,  H₁ += b,  H₂ += c,  H₃ += d
H₄ += e,  H₅ += f,  H₆ += g,  H₇ += h
```

#### Step 5: Produce Final Digest

Concatenate: `H₀ ‖ H₁ ‖ H₂ ‖ H₃ ‖ H₄ ‖ H₅ ‖ H₆ ‖ H₇` = 32 bytes.

### 3.3 Visual Diagram of One SHA-256 Round

```
    a       b       c       d       e       f       g       h
    |       |       |       |       |       |       |       |
    |       |       |       |       |       +---+---+       |
    |       |       |       |       |       |Ch(e,f,g)      |
    |       |       |       |       |       +---+           |
    |       |       |       |       +--Sigma1(e)            |
    |       |       |       |       |       |               |
    |       |       |       |       |    +--+--+--+---------+
    |       |       |       |       |    |                  
    |       |       |       |       |    | T1 = h + Sigma1 + Ch + K[t] + W[t]
    |       |       |       |       |    |                  
    +---+---+---+   |       |       |    |                  
    | Maj(a,b,c)|   |       |       |    |                  
    +---+       |   |       |       |    |                  
    |           |   |       |       |    |                  
    Sigma0(a)   |   |       |       |    |                  
    |           |   |       |       |    |                  
    +---+       |   |       |       |    |                  
    |   |       |   |       |       |    |                  
    T2=S0+Maj   |   |       |       |    |                  
    |           |   |       +---+   |    |                  
    +---+       |   |       |   |   |    |                  
        |       |   |       |   +---+----+                  
        |       |   |       |   |                           
    a=T1+T2   b=a  c=b    d=c  e=d+T1   f=e    g=f    h=g
```

### 3.4 Exact Test Vector Used on the Server (Test 4)

```
Input message: "Keystone-gem5-HSM"
              = 17 bytes of ASCII

SHA-256 Digest: 9a 7b 8f be 35 3e 18 89 31 7f 45 15 a8 72 b8 35
                0a 74 d6 21 9f 75 8d 74 5d 91 ef d6 fe 2a fc d1
              = 32 bytes

Verification: You can independently check by running:
    echo -n "Keystone-gem5-HSM" | sha256sum
    → 9a7b8fbe353e1889317f4515a872b8350a74d6219f758d745d91efd6fe2afcd1
```

The hash input is defined in `hsm_host.cpp:140`:
```c
const char* hash_msg = "Keystone-gem5-HSM";
```

### 3.5 Worked Example: Hashing "abc"

To illustrate the full algorithm, here's SHA-256 of "abc" (a NIST test vector):

```
Message:     61 62 63  (3 bytes)
After pad:   61 62 63 80 00...00 00 00 00 00 00 00 00 18  (64 bytes)
                                                      ^^^^ = 24 bits = 3 bytes × 8

Initial H:   6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19

After 64 rounds of compression:

Final digest: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
```

---

## 4. HMAC-SHA256 (Hash-based Message Authentication Code)

### 4.1 What Is It?

HMAC (RFC 2104) provides **message authentication** — it proves:
1. **Integrity**: The message was not tampered with.
2. **Authenticity**: Only someone with the secret key could have generated this tag.

Unlike encryption (which hides content), HMAC produces a **tag** (also called signature/MAC) that acts as a cryptographic checksum.

### 4.2 The HMAC Construction (RFC 2104)

```
HMAC(K, M) = H( (K' ⊕ opad) ‖ H( (K' ⊕ ipad) ‖ M ) )
```

Where:
- `K` = Secret key
- `M` = Message
- `H` = SHA-256
- `K'` = Key adjusted to block size:
  - If `|K| > 64`: `K' = SHA-256(K)` (hash it to 32 bytes)
  - If `|K| ≤ 64`: `K' = K ‖ 0x00...` (pad with zeros to 64 bytes)
- `ipad` = `0x36` repeated 64 times
- `opad` = `0x5C` repeated 64 times

### 4.3 Step-by-Step HMAC Computation

```
Step 1: Prepare the key
   K' = K padded to 64 bytes with 0x00

Step 2: Inner hash
   inner_key_pad = K' ⊕ (0x36 × 64)         [XOR each byte of K' with 0x36]
   inner_hash = SHA-256(inner_key_pad ‖ M)    [Hash the padded key concatenated with message]

Step 3: Outer hash
   outer_key_pad = K' ⊕ (0x5C × 64)         [XOR each byte of K' with 0x5C]
   HMAC = SHA-256(outer_key_pad ‖ inner_hash) [Hash the padded key concatenated with inner hash]
```

### 4.4 HMAC Diagram

```
                  Secret Key K (32 bytes)
                          |
                  Pad to 64 bytes = K'
                    +-----+-----+
                    |           |
                    v           v
              K' XOR ipad  K' XOR opad
              (0x36 x64)   (0x5C x64)
                    |           |
                    v           |
             +-----------+      |
    Message->|  SHA-256   |      |
             |  (inner)   |      |
             +-----+-----+      |
                   |             |
              inner_hash         |
              (32 bytes)         |
                   |             v
                   |      +-----------+
                   +----->|  SHA-256   |
                          |  (outer)   |
                          +-----+-----+
                                |
                           HMAC Tag
                          (32 bytes)
```

### 4.5 Implementation in Our Code

`crypto_sha256.c:119-145` — `hmac_sha256_init()`:
```c
// Step 1: Prepare key
memset(k_pad, 0, 64);
memcpy(k_pad, key, key_len);

// Step 2: Inner = SHA-256(K ⊕ ipad || ...)
for (i = 0; i < 64; i++) k_pad[i] ^= 0x36;
sha256_init(&ctx->inner);
sha256_update(&ctx->inner, k_pad, 64);

// Step 3: Outer = SHA-256(K ⊕ opad || ...)
for (i = 0; i < 64; i++) k_pad[i] ^= 0x36 ^ 0x5c;  // undo ipad, apply opad
sha256_init(&ctx->outer);
sha256_update(&ctx->outer, k_pad, 64);
```

`hmac_sha256_final()` (`crypto_sha256.c:151-156`):
```c
sha256_final(&ctx->inner, inner_hash);         // Complete inner hash
sha256_update(&ctx->outer, inner_hash, 32);    // Feed into outer
sha256_final(&ctx->outer, mac);                // Final HMAC tag
```

### 4.6 Exact Test Vectors Used on the Server (Tests 5–6)

**Test 5: HMAC-SHA256 Key Generation + Signing**

```
HMAC Key:    32 bytes randomly generated inside enclave (handle 0x1002)
             usage flags: SIGN | VERIFY

Message:     "Authenticate this critical financial transaction!"
             = 49 bytes of ASCII

HMAC Tag:    67 b7 ce fd d6 29 d5 1f 18 70 7c cd 67 11 14 b2
             b7 32 43 d6 84 45 30 bd e5 91 ac 21 a0 99 9b 82
             = 32 bytes
```

The message is defined in `hsm_host.cpp:26`:
```c
static const char* g_hmac_msg = "Authenticate this critical financial transaction!";
```

**Test 6: HMAC-SHA256 Verification**

The host sends the 32-byte HMAC tag + the original message to the enclave. The enclave recomputes the HMAC with the same key and compares:

```
Enclave receives:
   in_data[0..31]  = HMAC tag from Test 5
   in_data[32..80] = "Authenticate this critical financial transaction!"

Enclave:
   1. Recomputes HMAC-SHA256(key_0x1002, message)
   2. Compares recomputed tag with received tag using constant-time comparison
   3. If match → HSM_STATUS_OK (PASS)
```

The wire format is packed in `hsm_host.cpp:198-202`:
```c
memcpy(next_req.in_data, g_hmac_sig, 32);                    // 32-byte tag first
memcpy(next_req.in_data + 32, g_hmac_msg, strlen(g_hmac_msg)); // then message
next_req.in_data_len = 32 + strlen(g_hmac_msg);               // total: 32 + 49 = 81 bytes
```

### 4.7 Why Constant-Time Comparison Matters

A naive byte-by-byte comparison returns early on the first mismatch. An attacker can measure the timing to learn how many leading bytes of the HMAC match, allowing a **timing side-channel attack** to forge a valid tag byte by byte.

Our implementation uses constant-time `crypto_memcmp`: it XORs and ORs every byte regardless of mismatches, so the execution time is identical whether 0 bytes or all 32 bytes match.

---

## 5. PRNG (PSEUDORANDOM NUMBER GENERATOR)

### 5.1 What Is It?

The PRNG generates cryptographically secure random bytes used for:
- AES key generation (32 random bytes for AES-256)
- HMAC key generation (32 random bytes)

Since the enclave has no access to `/dev/urandom` (Linux syscalls are blocked by PMP isolation), it must generate randomness internally.

### 5.2 Design: Counter-based SHA-256 DRBG

```
Initialization:
   1. Read hardware cycle counter (rdcycle instruction)
   2. Hash it: state = SHA-256(rdcycle || optional_seed)
   3. Set counter = 1

Generating random bytes:
   1. block = SHA-256(state || counter || rdcycle)
   2. counter++
   3. state = SHA-256(block)    ← forward secrecy: old state is destroyed
   4. Output block (32 bytes)
   5. Repeat until enough bytes generated
```

### 5.3 Forward Secrecy

After each block is generated, the PRNG state is replaced with `SHA-256(block)`. This means that even if an attacker captures the current state, they **cannot recover previously generated random bytes** — the old state is gone.

This is `crypto_prng.c:47`:
```c
sha256_hash(block, 32, prng_state);  // Forward secrecy: overwrite state
```

### 5.4 Entropy Source

In the real hardware (RISC-V), `rdcycle` reads the CPU's cycle counter — a high-resolution timer that provides timing entropy from hardware execution jitter. In our implementation (`crypto_prng.c:9-13`), this is simulated with a Linear Congruential Generator (LCG) seeded with the constant `0x5A827999` (the SHA-1 round constant for rounds 0–19, chosen as a well-known non-trivial seed).

---

## 6. KEY STORE & HANDLE MANAGEMENT

### 6.1 What Is It?

The key store is a 64-slot table inside enclave memory that holds all generated cryptographic keys. Only **opaque integer handles** (starting at `0x1001`) are exposed to the host — never raw key material.

### 6.2 Key Slot Structure

Each slot stores (`key_store.h`):

```c
typedef struct {
    uint32_t handle;                    // Opaque handle (0x1001, 0x1002, ...)
    uint32_t key_type;                  // AES128, AES256, HMAC_SHA256
    uint32_t usage_flags;               // ENCRYPT | DECRYPT | SIGN | VERIFY
    size_t   key_len;                   // 16 (AES-128), 32 (AES-256 / HMAC)
    int      in_use;                    // 1 = active, 0 = free
    uint8_t  key_material[64];          // Raw secret key bytes
    uint8_t  public_key[32];            // (unused for symmetric keys; for asymmetric)
    int      in_use;                    // 1 = active, 0 = free
} key_slot_t;
```

### 6.3 Handle Allocation

```
HANDLE_BASE = 0x1000
First handle:  0x1000 + 1 = 0x1001  (AES-256 key, Test 1)
Second handle: 0x1000 + 2 = 0x1002  (HMAC-SHA256 key, Test 5)
```

### 6.4 Key Lookup Validation

When any operation references a handle, the key store:
1. Checks `handle >= HANDLE_BASE`
2. Scans all 64 slots for a matching `in_use && handle` entry
3. If not found → returns `HSM_STATUS_ERR_INVALID_HANDLE`

This is why forged handle `0xDEADBEEF` fails in Test 7 — no slot has that handle.

### 6.5 Secure Key Destruction

When a key is destroyed (`key_store.c:76-88`):

```c
memset(key_table[i].key_material, 0, sizeof(key_table[i].key_material));  // Zeroize key
memset(key_table[i].public_key, 0, sizeof(key_table[i].public_key));      // Zeroize public
key_table[i].in_use = 0;   // Mark slot free
key_table[i].handle = 0;   // Clear handle
```

After destruction, any subsequent operation using the old handle returns `ERR_INVALID_HANDLE` — this is verified in Test 8 (step 2: enclave tries to encrypt with destroyed handle, enclave rejects).

---

## 7. TEST CASE MAPPING — WHAT EACH TEST ACTUALLY EXERCISES

### Complete Test Flow (8 Tests, 11 Steps)

The host test suite (`hsm_host.cpp`) runs as a state machine using edge calls. Each step sends one command to the enclave and processes the previous response:

| Test | Step | HSM Command | Key Handle | Input Data | Expected Outcome | What It Proves |
|------|------|-------------|-----------|------------|-----------------|----------------|
| — | 0 | (enclave boot) | — | — | `HSM_STATUS_READY` | Enclave bootstrapped correctly |
| **1** | 1 | `GEN_KEY` (AES-256) | — | type=AES256, flags=ENC\|DEC | Handle `0x1001` returned | PRNG works, key store allocates |
| **2** | 2 | `ENCRYPT` | 0x1001 | IV + "IIT-Kgp..." (55B) | 64B ciphertext | AES-256 CBC + PKCS#7 works |
| **3** | 3 | `DECRYPT` | 0x1001 | IV + 64B ciphertext | Original 55B plaintext | Round-trip correctness |
| **4** | 4 | `DIGEST` | — | "Keystone-gem5-HSM" (17B) | 32B SHA-256 hash | SHA-256 compression works |
| **5a** | 5 | `GEN_KEY` (HMAC) | — | type=HMAC_SHA256, flags=SIGN\|VERIFY | Handle `0x1002` returned | Second key slot works |
| **5b** | 6 | `SIGN` | 0x1002 | "Authenticate this..." (49B) | 32B HMAC tag | HMAC-SHA256 inner/outer hash works |
| **6** | 7 | `VERIFY` | 0x1002 | [32B tag \| 49B msg] (81B) | `HSM_STATUS_OK` | Constant-time verification works |
| **7** | 8 | `ENCRYPT` | 0xDEADBEEF | IV + "TestSecretBlock!" (16B) | `ERR_INVALID_HANDLE` | Forged handles are rejected |
| **8a** | 9 | `DESTROY_KEY` | 0x1001 | — | `HSM_STATUS_OK` | Key zeroized in enclave memory |
| **8b** | 10 | `ENCRYPT` | 0x1001 | IV + "TestSecretBlock!" (16B) | `ERR_INVALID_HANDLE` | Destroyed key is truly unusable |

### IPC Wire Format

Every command/response passes through the 64KB shared memory buffer as:

**Request (`hsm_req_t`, 1060 bytes):**
```
Offset  Field           Size    Description
0       cmd_id          4B      Command enum (1-11)
4       key_handle      4B      Target key handle
8       key_type        4B      For key generation
12      usage_flags     4B      Permission bitmask
16      in_data_len     4B      Payload length
20      iv[16]          16B     AES initialization vector
36      in_data[1024]   1024B   Command payload
```

**Response (`hsm_resp_t`, 1044 bytes):**
```
Offset  Field           Size    Description
0       status          4B      Return code (0=OK, 4=INVALID_HANDLE, etc.)
4       key_handle      4B      Generated handle
8       key_type        4B      Key type info
12      usage_flags     4B      Key permissions
16      out_data_len    4B      Response payload length
20      out_data[1024]  1024B   Response payload (ciphertext, hash, etc.)
```

---

## APPENDIX: GALOIS FIELD GF(2⁸) ARITHMETIC (for AES)

AES performs all byte-level arithmetic in the **Galois Field GF(2⁸)** with the irreducible polynomial `m(x) = x⁸ + x⁴ + x³ + x + 1` (hex: `0x11B`).

### Addition in GF(2⁸)
Addition is simply **XOR**:
```
a + b = a ⊕ b
```
There are no carries. `a + a = 0` for all `a` (every element is its own additive inverse).

### Multiplication in GF(2⁸)
Multiplication is **polynomial multiplication modulo `m(x)`**. The `xtime()` function handles multiplication by `x` (i.e., by 2):

```
xtime(a) = a << 1           if bit 7 of a is 0
xtime(a) = (a << 1) ⊕ 0x1B  if bit 7 of a is 1    (reduce by m(x))
```

General multiplication uses repeated `xtime` and XOR (like binary exponentiation):
```c
uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t res = 0;
    while (y) {
        if (y & 1) res ^= x;   // add x if current bit of y is set
        x = xtime(x);          // double x in GF(2⁸)
        y >>= 1;               // next bit of y
    }
    return res;
}
```

This is `crypto_aes.c:62-70`.

### Example: 0x57 × 0x83

```
0x83 = 10000011₂

Step 1: bit 0 = 1 → result = 0x57
Step 2: bit 1 = 1, x = xtime(0x57) = 0xAE → result = 0x57 ⊕ 0xAE = 0xF9
Step 3-6: bits 2-5 = 0, x doubles each time via xtime()
Step 7: bit 7 = 1, x = xtime⁷(0x57) = 0x38 → result = 0xF9 ⊕ 0x38 = 0xC1

Answer: 0x57 × 0x83 = 0xC1 in GF(2⁸)
```

---

*This document is a companion to `MASTER_REFERENCE.md`. Together they contain everything needed for the BTP report, presentation, and viva defense.*
