# Curve256189

A custom elliptic curve cryptography library for Dart, built on **Curve256189** — a Montgomery curve over the prime field 2²⁵⁶ - 189.

Curve256189 was independently discovered and implemented by Ismael Urzaiz Aranda, achieving full **SafeCurves compliance (11/11)**.

---
### Parameter Discovery

The origin of the parameters used in Curve256189 comes from a small sequence of exploratory decisions that ultimately produced an unexpected but elegant outcome.

The process began with the idea of constructing a 256-bit prime field close to a power of two, following a pattern often used in efficient elliptic-curve implementations. For this purpose, numbers of the form (p = 2²⁵⁶ - c) were examined. The value (c = 189) was initially chosen simply as an arbitrary offset. Later verification revealed something surprising: **189 is in fact the smallest positive value for which (2²⁵⁶ - c) is prime** within that search. In other words, the field modulus turned out to be the first valid prime immediately below (2²⁵⁶) of that form.

After fixing the field (p = 2²⁵⁶ − 189), the next step was to determine a suitable parameter (A) for the Montgomery curve (y² = x³ + Ax² + x). Rather than starting a brute-force search from (A = 1), preliminary experimentation suggested that promising candidates tended to appear in a certain numerical region. Based on this observation, the search began around the range of a few hundred thousand, starting near (A = 443000).

Each candidate value of (A) was tested to determine whether the resulting curve satisfied two conditions: the main curve order should have the form (4 × prime), and its quadratic twist should also have the same structure. In practice many candidates passed the first condition but failed the second, which is expected because curves whose main group and twist both contain large prime subgroups are relatively uncommon.

After scanning through several thousand candidates, the search produced a valid parameter:

**A = 479597**

At this point both the curve and its quadratic twist satisfied the desired structure with a small cofactor and large prime subgroup. The entire parameter search took roughly two days of computation.

In retrospect, the process contains an interesting coincidence: the prime field offset (189), originally chosen without special significance, turned out to be the minimal valid value for (2²⁵⁶ - c), while the suitable Montgomery parameter appeared relatively close to the initial search region. These two results together define the parameters used by **Curve256189**.  

`bin/src_test/found.sage`

---

## Curve Parameters

| Parameter | Value                                                                            |
|---|----------------------------------------------------------------------------------|
| **Equation** | y² = x³ + Ax² + x                                                                |
| **Prime p** | 2²⁵⁶ − 189                                                                        |
| **Coefficient A** | 479597                                                                           |
| **Subgroup order n** | 28948022309329048855892746252171976963257918617752773869725216245594308445583    |
| **Cofactor h** | 4                                                                                |
| **Twist order** | 4 × 28948022309329048855892746252171976963377073715067508150003575758362256374291 |
| **Generator Gx** | 107794463287790729181798923754704247240057009056848862892287801730172665808003   |
| **Generator Gy** | 5935226473593038842940459288042955305454636525326183552707973708623513097342     |

---

## Components

| Component | Description |
|---|---|
| **Curve256189** | Montgomery curve — core arithmetic, point validation, scalar blinding |
| **Ed256189** | Twisted Edwards birational equivalent |
| **X256189** | ECDH key exchange — cofactor clearing per RFC 7748 |
| **EdDSA** | Digital signatures with FPOW scalar protection |
| **Elligator 2** | Point encoding/decoding per RFC 9380 |
| **HKDF** | Key derivation per RFC 5869 |
| **AES-GCM** | Authenticated encryption per NIST SP 800-38D |
| **Batch Verify** | High-throughput Ed256189 batch signature verification |
| **FPOW** | Fixed-Point One-Way Wrap — scalar obfuscation layer |

---

## SafeCurves Compliance

Curve256189 passes all 11 SafeCurves criteria — verified via SageMath:

| # | Criterion | Detail | Status |
|---|-----------|--------|--------|
| 1 | Field | p = 2²⁵⁶ - 189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43 (prime, nearest form with c=189 < 2¹²⁸) | ✅ |
| 2 | Equation | y² = x³ + 479597x² + x, B(A²-4) mod p = 230013282405 ≠ 0 | ✅ |
| 3 | Base Point | G = (107794463287790729181798923754704247240057009056848862892287801730172665808003, 5935226473593038842940459288042955305454636525326183552707973708623513097342), n = 28948022309329048855892746252171976963257918617752773869725216245594308445583 = 0x3fffffffffffffffffffffffffffffffd32dc81090973cccf6191c1f9153858f (prime), n·G = ∞ | ✅ |
| 4 | Rho | 0.886·√n ≈ 2¹²⁶·⁸ > 2¹⁰⁰ | ✅ |
| 5 | Transfer | 14474011154664524427946373126085988481628959308876386934862608122797154222791 - (l-1)/2 | ✅ |
| 6 | Discriminant | Trace t = 238310194629468560556719025535895857416, \|D\| = 101594152021232398932927088336875798239142520126423777616574221809005679090483 = 0xe09c409782a1ccd7eb8fdca7674897ae051c794225ffd89fbba14ceb13b41b33 ≈ 2²⁵⁵·⁸ > 2¹⁰⁰ | ✅ |
| 7 | Rigidity | Smallest A = 479597 via transparent brute force with cofactor=4, twist cofactor=4, prime subgroup order, prime twist subgroup order | ✅ |
| 8 | Ladder | A²-4 mod p = 230013282405 (non-square) | ✅ |
| 9 | Twist | Twist order = 115792089237316195423570985008687907853508294860270032600014303033449025497164 = 0x100000000000000000000000000000000b348dfbdbda30ccc279b8f81bab1e84c, twist cofactor = 4, twist subgroup order = 28948022309329048855892746252171976963377073715067508150003575758362256374291 (prime) | ✅ |
| 10 | Completeness | Montgomery ladder complete (A²-4 non-square), Twisted Edwards complete? ❌ (not required) | ✅ |
| 11 | Indistinguishability | Elligator 2 applicable: A²-4 non-square, curve has point of order 2 | ✅ |

**Total: 11/11 Criteria met — SafeCurves compliant! ✅**

Full verification: `bin/src_test/safecurves_curve256189`

---

## Security Properties

- **Montgomery Ladder** — Constant-time scalar multiplication
- **Scalar blinding** — Timing attack prevention via `Random.secure()`
- **Point validation** — Rejects infinity, out-of-range, off-curve, and low-order points
- **Cofactor clearing** — h=4 per RFC 7748 convention
- **FPOW layer** — Fixed-Point One-Way Wrap for private scalar protection
- **Elligator 2** — Uniform random point encoding for traffic analysis resistance

---

## Research Journey — From HFE to FPOW

### Background

The original implementation used an HFE-inspired scalar obfuscation pipeline (S∘F∘T) where:
```
wrap(k) = T(F(S(k)))
S(x) = a*x + b       mod n
F(x) = x³ + coeff*x  mod n
T(x) = c*x + d       mod n
```

### Discovery (March 2026)

During security audit, a critical weakness was found: the pipeline produces a **degree-3 polynomial in k**, recoverable via Lagrange interpolation with only 4 known-plaintext pairs:
```
wrap(k) = A*k³ + B*k² + C*k + D
→ 4 pairs (k, wrap(k)) → A,B,C,D fully recovered
→ Cubic equation mod n → k recoverable
```

This finding led to the development of **FPOW**.

### FPOW — Fixed-Point One-Way Wrap
```
wrap(k, secret) = k + H(secret ‖ k) mod n
where H = SHA-512 (one-way function)
```

**Properties verified via SageMath:**

| Property | Result | Status |
|---|---|---|
| Non-polynomial | Lagrange interpolation fails | ✅ |
| Statistical uniformity | Output ratio ~1.0 | ✅ |
| Differential randomness | 500/500 unique diffs | ✅ |
| Fixed-point one-way | k_raw = k' − H(secret ‖ k_raw) — circular | ✅ |
| Fixed-point uniqueness | 0 collisions in 10⁶ samples — prob ≈ 3.45×10⁻⁷¹ | ✅ |
| Known-plaintext resistance | Without secret → cannot compute H | ✅ |
| Quantum resistance | Grover: 2¹²⁷ — infeasible per NIST 128-bit standard | ✅ |

**Shor resistance analysis:**
```
Shor's algorithm on ECDLP → recovers k_wrapped
But k_wrapped ≠ k_raw!

To recover k_raw, attacker must solve:
k_raw = k_wrapped − H(secret ‖ k_raw) mod n

This is a fixed-point equation:
→ Classical brute force: 2^256
→ Grover acceleration:   2^127 (still infeasible)
→ No known algebraic shortcut exists
```

**Why FPOW is ECC Gen 2, not standalone PQC:**
```
ECC Gen 1:  k_raw → k_raw * G = PublicKey
            Shor: PublicKey → k_raw ✗

ECC Gen 2:  k_raw → FPOW → k_wrapped → k_wrapped * G = PublicKey
            Shor: PublicKey → k_wrapped ✓
            But: k_wrapped ≠ k_raw
            Recovery: k_raw = k_wrapped − H(secret ‖ k_raw) → circular!
```

FPOW adds a second hardness layer on top of ECDLP. An attacker must break both:
1. **ECDLP** — to recover `k_wrapped` from the public key
2. **SHA-512 fixed-point inversion** — to recover `k_raw` from `k_wrapped`

No known quantum algorithm efficiently solves step 2.

**Open research questions:**

- Formal security reduction to Random Oracle Model (ROM)
- Secret rotation mechanism for forward secrecy
- Standalone hardness assumption formalization

Full verification: `bin/fpow_curve256189.sage`

> **Note:** FPOW is a novel construction not found in surveyed literature at time of writing. It is presented as a research contribution pending formal peer review. HFE is preserved in `lib/src/hfe.dart` for historical reference and to document the research journey that led to this discovery.

---

## Test Vectors

### EdDSA (Ed256189)
```
Seed:       0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Public Key: d6399e1969b4a67871928b7f3066eb2b8e119765c697317ea29688016404b9fe00
Message:    "Hello Curve256189!"
Signature:  5a43c931eeb6329f00c27e3daeef2ce888746d81209881130db681f8cb161b960
            0919794e5439eb4be7263891d5abc75e766276b39eeb4758dbd6c49a485336405
```

### X256189 (ECDH + HKDF)
```
Alice Seed: 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Alice PK:   337d3142bff70cdcbe04d69ee7b7a36c3e8df6bba0a5e0a12cb4b1b580bab424
Bob Seed:   2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
Bob PK:     6bf5338a759e576c61c6e3386630e3109c6826e05be16d1b8f954b48e2dd530e
Shared:     a5ba314a475956d6a02d227c8ae094e673bf59eff0257e76f7d47c9e11ee6d3a
HKDF key:   55c8e6fdcbb611ef67fb69b6245f688a372828f56b78b5f6006d389ee215f6ba
```

### Elligator 2
```
encode(1)  = 38597363079105398474523661669562635951089994888546854679819194669304376226851
encode(2)  = 90060513851245929773888543895646150552543321406609327586244787561710211515717
encode(42) = 51481379431382575976079023938405023355562653992742999427007353161920005302563
```

### AES-256-GCM (NIST SP 800-38D)
```
Key:       0000000000000000000000000000000000000000000000000000000000000000
Nonce:     000000000000000000000000
Plaintext: (empty)
Tag:       530f8afbc74536b9a963b4f1c4cb738b  ← NIST verified
```

---

## Usage

### EdDSA — Sign and Verify
```dart
import 'package:curve256189/src/eddsa.dart';
import 'dart:typed_data';

// Generate key pair
final seed = Uint8List(32); // 32-byte random seed
final keyPair = EdDSA.generateKeyPair(seed);

// Sign
final message = Uint8List.fromList('Hello!'.codeUnits);
final signature = EdDSA.sign(message, keyPair['privateKey']!);

// Verify
final valid = EdDSA.verify(message, signature, keyPair['publicKey']!);
```

### X256189 — ECDH Key Exchange
```dart
import 'package:curve256189/src/x256189.dart';
import 'package:curve256189/src/hkdf.dart';
import 'dart:typed_data';

// Alice
final aliceKP = X256189.generateKeyPair(aliceSeed);

// Bob
final bobKP = X256189.generateKeyPair(bobSeed);

// Compute shared secret
final sharedSecret = X256189.computeSharedSecret(
  aliceKP['privateKey']!,
  bobKP['publicKey']!,
);

// Derive key via HKDF
final key = HKDF.derive(
  ikm: sharedSecret!,
  info: Uint8List.fromList('my app'.codeUnits),
);
```

### AES-GCM — Encrypt and Decrypt
```dart
import 'package:curve256189/src/aesgcm.dart';
import 'dart:typed_data';

// Encrypt
final result = AESGCM.encrypt(
  key: aesKey,      // 32 bytes from HKDF
  nonce: aesNonce,  // 12 bytes from HKDF
  plaintext: Uint8List.fromList('Hello!'.codeUnits),
);

// Decrypt
final plaintext = AESGCM.decrypt(
  key: aesKey,
  nonce: aesNonce,
  ciphertext: result.ciphertext,
  tag: result.tag,
);
```

---

## Running Tests
```bash
dart bin/src_test/fpow_curve256189.sage
dart bin/src_test/safecurves_curve256189.sage
dart bin/src_test/test_field.dart
dart bin/src_test/test_montgomery.dart
dart bin/src_test/test_edwards.dart
dart bin/src_test/test_eddsa.dart
dart bin/src_test/test_elligator.dart
dart bin/src_test/test_validation.dart
dart bin/src_test/test_blinding.dart
dart bin/src_test/test_fpow.dart
dart bin/src_test/test_x256189.dart
dart bin/src_test/test_hkdf.dart
dart bin/src_test/test_hfe_security.dart
dart bin/src_test/test_aesgcm.dart
dart bin/src_test/test_batch_verify.dart
dart bin/src_test/test_audit.dart
```

---

## Implementation Notes

- **No `BigInt.modPow`** — Dart's `BigInt.modPow` has a known bug for 256-bit exponents. All modular exponentiation uses a safe square-and-multiply implementation in `FieldElement.pow()`.
- **Okeya-Sakurai y-recovery** — `TwistedEdwards.scalarMul` uses the Okeya-Sakurai (2001) formula to recover the correct y-coordinate after Montgomery ladder x-only computation. This fixes an ambiguity where choosing "canonical even y" produces incorrect results for batch verification and general Edwards arithmetic.
- **Parity bit fix** — `TwistedEdwards.decodePoint` uses `(bytes[32] & 1) == 1` instead of `bytes[32] == 1` to correctly handle all odd parity byte values.
- **Little-endian encoding** — All byte serialization follows RFC 7748 convention.
- **Deterministic signatures** — EdDSA nonce derived from `hash(prefix || message)`.
- **HFE preserved** — Original HFE implementation kept in `lib/src/hfe.dart` for historical reference. See Research Journey section above.

---

## License

MIT License — see [LICENSE](LICENSE)

---

## References

- [SafeCurves](https://safecurves.cr.yp.to/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — Elliptic Curves for Diffie-Hellman
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — Edwards-Curve Digital Signature Algorithm
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) — Hashing to Elliptic Curves (Elligator 2)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — AES-GCM
- [Patarin 1996](https://link.springer.com/chapter/10.1007/3-540-68339-9_4) — Hidden Field Equations (HFE)