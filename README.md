# Curve256189

A custom elliptic curve cryptography library for Dart, built on **Curve256189** — a Montgomery curve over the prime field 2²⁵⁶ - 189.

Curve256189 was independently discovered and implemented by Ismael Urzaiz Aranda, achieving full **SafeCurves compliance (11/11)**.

---

## Curve Parameters

| Parameter | Value |
|---|---|
| **Equation** | y² = x³ + Ax² + x |
| **Prime p** | 2²⁵⁶ - 189 |
| **Coefficient A** | 479597 |
| **Cofactor h** | 4 |
| **Subgroup order n** | 28948022309329048855892746252171976963257918617752773869725216245594308445583 |
| **Generator Gx** | 107794463287790729181798923754704247240057009056848862892287801730172665808003 |
| **Generator Gy** | 5935226473593038842940459288042955305454636525326183552707973708623513097342 |

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
|---|---|---|---|
| 1 | Field | p = 2²⁵⁶ - 189 is prime | ✅ |
| 2 | Equation | B(A²-4) mod p = 230013282405 ≠ 0 | ✅ |
| 3 | Base Point | n is prime, n·G = ∞ | ✅ |
| 4 | Rho | 0.886·√n ≈ 2^126.8 > 2^100 | ✅ |
| 5 | Transfer | Embedding degree k > 10000 | ✅ |
| 6 | Discriminant | \|D\| ≈ 2^255.8 > 2^100 | ✅ |
| 7 | Rigidity | Smallest A via transparent brute force | ✅ |
| 8 | Ladder | A²-4 non-square mod p | ✅ |
| 9 | Twist | Twist cofactor = 4, twist subgroup prime | ✅ |
| 10 | Completeness | Montgomery Ladder complete (A²-4 non-square) | ✅ |
| 11 | Indistinguishability | Elligator 2 — A²-4 non-square, order-2 point exists | ✅ |

**Score: 11/11 — SafeCurves Compliant ✅**

Full verification: `bin/safecurves_curve256189.sage`

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
S(x) = a*x + b  mod n
F(x) = x³ + coeff*x  mod n
T(x) = c*x + d  mod n
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
|---|---|-|
| Non-polynomial | Lagrange interpolation fails | ✅ |
| Statistical uniformity | Output ratio ~1.0 | ✅ |
| Differential randomness | 500/500 unique diffs | ✅ |
| Fixed-point one-way | k_raw = k' − H(secret ‖ k_raw) — circular | ✅ |
| Quantum resistance | Grover: 2^128 — infeasible | ✅ |

**Shor resistance analysis:**
```
Shor's algorithm on ECDLP → recovers k_wrapped
But k_wrapped ≠ k_raw!

To recover k_raw, attacker must solve:
k_raw = k_wrapped − H(secret ‖ k_raw) mod n

This is a fixed-point equation:
→ Classical brute force: 2^256
→ Grover acceleration:   2^128 (still infeasible)
→ No known algebraic shortcut
```

Full verification: `bin/fpow_curve256189.sage`

> **Note:** FPOW is a novel construction not found in surveyed literature at time of writing. It is kept as a research contribution pending formal peer review. HFE is preserved in `lib/src/hfe.dart` for historical reference.

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
dart bin/test_field.dart
dart bin/test_montgomery.dart
dart bin/test_edwards.dart
dart bin/test_eddsa.dart
dart bin/test_elligator.dart
dart bin/test_validation.dart
dart bin/test_blinding.dart
dart bin/test_x256189.dart
dart bin/test_hkdf.dart
dart bin/test_hfe_security.dart
dart bin/test_aesgcm.dart
dart bin/test_batch_verify.dart
dart bin/test_audit.dart
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