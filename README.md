<p align="center">
  <img src="banner.svg" alt="Curve256189" width="870">
</p>

A pure-Dart elliptic curve cryptography library built on **Curve256189**, a Montgomery curve y² = x³ + Ax² + x over the prime field 𝔽ₚ with p = 2²⁵⁶ − 189.

Curve256189 was designed and implemented by Ismael Urzaiz Aranda. It satisfies all eleven [SafeCurves](https://safecurves.cr.yp.to/) criteria (11/11), verified with SageMath (`dev/unit/safecurves_curve256189.sage`). The library provides X256189 (ECDH), XEdDSA (signatures), Elligator 2 (point encoding), HKDF, and AES-GCM, all implemented in Dart.

---

## Parameter Selection

The parameters of Curve256189 were selected against explicit design criteria rather than ad hoc. The selection procedure is deterministic and reproducible (`dev/unit/found.sage`).

### Design Criteria

1. **Field:** a 256-bit prime p = 2²⁵⁶ − c with small c, allowing efficient modular reduction.
2. **Group order:** #E = 4 · n with n prime (cofactor h = 4).
3. **Twist security:** the quadratic twist has order #Eᵗ = 4 · nᵗ with nᵗ prime (twist cofactor 4).
4. **Ladder completeness:** A² − 4 is a quadratic non-residue modulo p. The Montgomery ladder is then complete, and the curve has exactly one point of order 2, which Elligator 2 requires.
5. **Rigidity:** the coefficient A is fixed by a fully specified, transparent search procedure, with no unexplained constants.

### Field Selection

Candidates of the form p = 2²⁵⁶ − c were enumerated in order of increasing c. The value c = 189 is the smallest positive integer for which 2²⁵⁶ − c is prime, so p = 2²⁵⁶ − 189 is the largest prime below 2²⁵⁶. This keeps the modulus as close to 2²⁵⁶ as possible and satisfies the SafeCurves field criterion c < 2¹²⁸.

### Coefficient Search

With p fixed, the Montgomery coefficient A was determined by an exhaustive search over 0 ≤ A ≤ 10⁶. Since p ≡ 3 (mod 4), replacing A by −A exchanges the curve with its quadratic twist, so restricting the search to non-negative A is without loss of generality.

For each candidate A, the group order #E and the twist order #Eᵗ were computed, and the cofactor pair (h, hᵗ) was recorded for all combinations with h, hᵗ ∈ {4, 8}: (4, 4), (4, 8), (8, 4) and (8, 8). A candidate was admissible if #E = h · n and #Eᵗ = hᵗ · nᵗ with n and nᵗ prime, and A² − 4 is a quadratic non-residue modulo p.

Within the searched range, A = **479597** is the only value yielding the cofactor pair (4, 4). It is therefore the smallest admissible coefficient for the strictest cofactor profile, uniquely determined by the criteria above. The search required approximately two days of computation.

### Resulting Parameters

| Parameter | Value |
|---|---|
| Prime p | 2²⁵⁶ − 189 |
| Coefficient A | 479597 |
| Cofactor h | 4 |
| Twist cofactor | 4 |
| A² − 4 mod p | 230013282405 (non-square) |

The full parameter set, including the subgroup orders n and nᵗ and the generator G, is listed under [Curve Parameters](#curve-parameters).

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
| --- | --- |
| **Curve256189** | Montgomery curve: core arithmetic, point validation, scalar blinding |
| **Ed256189** | Birationally equivalent twisted Edwards form (compatibility layer) |
| **X256189** | ECDH key exchange with cofactor clearing per RFC 7748 |
| **XEdDSA** | x-only Schnorr-style signatures on the Montgomery curve |
| **Elligator 2** | Point encoding and decoding per RFC 9380 |
| **HKDF** | Key derivation per RFC 5869 |
| **AES-GCM** | Authenticated encryption per NIST SP 800-38D |
| **Batch Verify** | High-throughput batch verification of XEdDSA signatures |

---

## SafeCurves Compliance

Curve256189 satisfies all 11 SafeCurves criteria, verified with SageMath:

| # | Criterion | Detail | Status |
| --- | --- | --- | --- |
| 1 | Field | p = 2²⁵⁶ - 189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43 (prime, nearest form with c=189 < 2¹²⁸) | Pass |
| 2 | Equation | y² = x³ + 479597x² + x, B(A²-4) mod p = 230013282405 ≠ 0 | Pass |
| 3 | Base Point | G = (107794463287790729181798923754704247240057009056848862892287801730172665808003, 5935226473593038842940459288042955305454636525326183552707973708623513097342), n = 28948022309329048855892746252171976963257918617752773869725216245594308445583 = 0x3fffffffffffffffffffffffffffffffd32dc81090973cccf6191c1f9153858f (prime), n·G = ∞ | Pass |
| 4 | Rho | 0.886·√n ≈ 2¹²⁶·⁸ > 2¹⁰⁰ | Pass |
| 5 | Transfer | Embedding degree = (ℓ-1)/2 = 14474011154664524427946373126085988481628959308876386934862608122797154222791, where ℓ = n | Pass |
| 6 | Discriminant | Trace t = 238310194629468560556719025535895857416, \|D\| = 101594152021232398932927088336875798239142520126423777616574221809005679090483 = 0xe09c409782a1ccd7eb8fdca7674897ae051c794225ffd89fbba14ceb13b41b33 ≈ 2²⁵⁵·⁸ > 2¹⁰⁰ | Pass |
| 7 | Rigidity | A = 479597 is the unique coefficient in 0 ≤ A ≤ 10⁶ with cofactors (4, 4), prime subgroup order and prime twist subgroup order; the exhaustive scan also covered (4, 8), (8, 4) and (8, 8) | Pass |
| 8 | Ladder | A²-4 mod p = 230013282405 (non-square) | Pass |
| 9 | Twist | Twist order = 115792089237316195423570985008687907853508294860270032600014303033449025497164 = 0x100000000000000000000000000000000b348dfbdbda30ccc279b8f81bab1e84c, twist cofactor = 4, twist subgroup order = 28948022309329048855892746252171976963377073715067508150003575758362256374291 (prime) | Pass |
| 10 | Completeness | Montgomery ladder complete (A²-4 non-square); twisted Edwards completeness not required | Pass |
| 11 | Indistinguishability | Elligator 2 applicable: A²-4 non-square, curve has a point of order 2 | Pass |

**Total: 11/11 criteria met.**

Full verification: `dev/unit/safecurves_curve256189.sage`

---

## Security Properties

- **Montgomery ladder:** scalar multiplication executes a uniform sequence of operations per scalar bit.
- **Scalar blinding:** randomized multiples of the full curve order `4n` via `Random.secure()`, which preserves the result for every curve point and reduces timing leakage.
- **Point validation:** rejects the point at infinity, out-of-range coordinates, off-curve points, and low-order points.
- **Cofactor clearing:** h = 4, following the RFC 7748 convention.
- **Strict signature verification:** canonical `s < n`, exact 64-byte signatures, canonical even-`y` decoding, and prime-order subgroup membership for both `R` and `P`.
- **Non-malleable signatures:** canonical scalars and full-point equality reject sign-flipped `R` and `s + n` variants.
- **Elligator 2:** uniform random-looking point encoding, providing resistance to traffic analysis.

### Side-Channel Considerations

The implementation relies on Dart's `BigInt`, whose arithmetic is not guaranteed to run in constant time. The ladder structure and scalar blinding reduce timing leakage, but they do not constitute a formal constant-time guarantee. Deployments with strong side-channel requirements should account for this.

---

## Test Vectors

### XEdDSA
```
Seed:       0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Public Key: 337d3142bff70cdcbe04d69ee7b7a36c3e8df6bba0a5e0a12cb4b1b580bab424
Message:    "Hello Curve256189!"
Signature:  c87e2d535cab5c2ede5993907c4c8d97aa6be84dd9de5b0b4b39e56d4d084284
            ee7a80cfbff274f44f74b7a03b49b744c481f702a80c35a93ff03ad11cef142e
```

The public key is identical to the X256189 key for the same seed, because both
derive the cofactor-cleared scalar. The signature is `x(R) || s`, both
little-endian 32-byte values. XEdDSA is **not** wire-compatible with RFC 8032
EdDSA.

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
Tag:       530f8afbc74536b9a963b4f1c4cb738b (NIST verified)
```

---

## Usage

### XEdDSA: Sign and Verify
```dart
import 'package:curve256189/curve256189.dart';
import 'dart:typed_data';

// Generate key pair from a 32-byte seed
final seed = Uint8List(32); // use a cryptographically random seed
final keyPair = XEdDSA.generateKeyPair(seed);

// Sign (deterministic, 64-byte signature)
final message = Uint8List.fromList('Hello!'.codeUnits);
final signature = XEdDSA.sign(message, keyPair['privateKey']!);

// Verify
final valid = XEdDSA.verify(message, signature, keyPair['publicKey']!);
```

Batch verification uses the same 64-byte signatures and 32-byte public keys:

```dart
final ok = BatchVerify.verify([
  SignatureBundle(
    message: message,
    signature: signature,
    publicKey: keyPair['publicKey']!,
  ),
]);
```

### X256189: ECDH Key Exchange
```dart
import 'package:curve256189/curve256189.dart';
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

### AES-GCM: Encrypt and Decrypt
```dart
import 'package:curve256189/curve256189.dart';
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
SageMath dev/unit/safecurves_curve256189.sage
dart dev/unit/test_aesgcm.dart
dart dev/unit/test_batch_verify.dart
dart dev/unit/test_blinding.dart
dart dev/unit/test_xeddsa.dart
dart dev/unit/test_edwards.dart
dart dev/unit/test_elligator.dart
dart dev/unit/test_field.dart
dart dev/unit/test_hkdf.dart
dart dev/unit/test_montgomery.dart
dart dev/unit/test_validation.dart
dart dev/unit/test_x256189.dart
```

---

## Implementation Notes

- **No `BigInt.modPow`:** Dart's `BigInt.modPow` has a known defect for 256-bit exponents. All modular exponentiation therefore uses a square-and-multiply implementation in `FieldElement.pow()`, verified by `dev/integration/test_modpow.dart`.
- **Okeya-Sakurai y-recovery:** `Montgomery.scalarMulFull` uses the Okeya-Sakurai (2001) formula to recover a full point from the x-only ladder, with a double-and-add fallback if the formula degenerates. Scalar blinding adds a random multiple of `4n`, so it is correct for low-order and mixed-order points as well.
- **x-only signatures:** XEdDSA avoids Edwards addition entirely. Signing and verification canonicalise `P` and `R` to the even-`y` representative and check the exact full-point equation `[s]G == R + [h]P`, so variants such as `(x(R), n - s)` or a sign-flipped `R` cannot be accepted.
- **Strict validation:** signatures must be exactly 64 bytes, `s < n`, and both `R` and `P` must decode to canonical even-`y` points in the prime-order subgroup. Low-order and mixed-order public keys are rejected.
- **Parity bit handling:** `TwistedEdwards.decodePoint` tests `(bytes[32] & 1) == 1` rather than `bytes[32] == 1`, so that all odd parity byte values are decoded correctly.
- **Little-endian encoding:** all byte serialization follows the RFC 7748 convention.
- **Deterministic signatures:** the XEdDSA nonce is derived as `SHA-512(domain || 0x01 || prefix || counter || message) mod n`, with the challenge as `SHA-512(domain || 0x02 || x(R) || x(P) || message) mod n`.

### XEdDSA Scheme Summary

| Item | Value |
|---|---|
| Domain separation | `Curve256189-XEdDSA-v1` |
| Secret derivation | `sk = SHA-512(seed)[0..32]`, clamped; `a = 4·sk mod n` |
| Public key | `x([a]G)`, 32-byte little-endian, canonical even `y` |
| Nonce | `r = SHA-512(domain ‖ 0x01 ‖ prefix ‖ counter ‖ message) mod n` |
| Challenge | `h = SHA-512(domain ‖ 0x02 ‖ x(R) ‖ x(P) ‖ message) mod n` |
| Signature | `x(R) ‖ s`, where `s = r + h·a mod n` |
| Verification | `[s]G == R + [h]P` as full points, after subgroup checks |

This is a Curve256189-specific x-only construction inspired by XEdDSA-style
designs. It is not the Signal XEdDSA wire format and has not undergone an
independent cryptographic audit; review it before deploying it in a
security-critical system.

---

## License

MIT License. See [LICENSE](LICENSE).

---

## References

- [SafeCurves](https://safecurves.cr.yp.to/)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748): Elliptic Curves for Diffie-Hellman
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Edwards-Curve Digital Signature Algorithm
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380): Hashing to Elliptic Curves (Elligator 2)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869): HKDF
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final): AES-GCM
- [Patarin 1996](https://link.springer.com/chapter/10.1007/3-540-68339-9_4): Hidden Field Equations (HFE)