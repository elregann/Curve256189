<p align="center">
  <img src="banner.svg" alt="Curve256189" width="870">
</p>

A pure-Dart elliptic curve cryptography library built on **Curve256189**, a Montgomery curve y² = x³ + Ax² + x over the prime field 𝔽ₚ with p = 2²⁵⁶ − 189.

Curve256189 was designed and implemented by Ismael Urzaiz Aranda. It satisfies all eleven [SafeCurves](https://safecurves.cr.yp.to/) criteria (11/11), verified with SageMath (`tool/safecurves_curve256189.sage`). The library provides X256189 (ECDH), Ed256189 (RFC 8032-shaped EdDSA signatures), XEdDSA (superseded signatures), Elligator 2 (point encoding), HKDF, and AES-GCM, all implemented in Dart. Its Edwards layer uses the dual complete curve E_{d,a}, so affine Edwards addition has no exceptional inputs.

Ed256189 is specified in [doc/ed256189.md](doc/ed256189.md). XEdDSA is specified in [doc/xeddsa.md](doc/xeddsa.md); it is kept for backwards compatibility and is marked superseded. It will be removed in a future major release.

---

## Parameter Selection

The parameters of Curve256189 were selected against explicit design criteria rather than ad hoc. The selection procedure is deterministic and reproducible (`tool/find_prime.sage`).

### Design Criteria

1. **Field:** a 256-bit prime p = 2²⁵⁶ − c with small c, allowing efficient modular reduction.
2. **Group order:** #E = 4 · n with n prime (cofactor h = 4).
3. **Twist security:** the quadratic twist has order #Eᵗ = 4 · nᵗ with nᵗ prime (twist cofactor 4).
4. **Ladder completeness:** A² − 4 is a quadratic non-residue modulo p. The Montgomery ladder is then complete, and the curve has exactly one point of order 2, which Elligator 2 requires.
5. **Edwards completeness:** A − 2 is a quadratic residue (equivalently A + 2 is a non-residue, because A² − 4 is a non-residue), so the dual Edwards model E_{d,a} used by Ed256189 has a complete addition law.
6. **Rigidity:** the coefficient A is the first hit of a fully specified, transparent deterministic scan from 0, with no unexplained constants.

### Field Selection

Candidates of the form p = 2²⁵⁶ − c were enumerated in order of increasing c. The value c = 189 is the smallest positive integer for which 2²⁵⁶ − c is prime, so p = 2²⁵⁶ − 189 is the largest prime below 2²⁵⁶. This keeps the modulus as close to 2²⁵⁶ as possible and satisfies the SafeCurves field criterion c < 2¹²⁸.

### Coefficient Search

With p fixed, the Montgomery coefficient A was determined by a deterministic scan over A = 0, 1, 2, … . Since p ≡ 3 (mod 4), replacing A by −A exchanges the curve with its quadratic twist, so restricting the scan to non-negative A is without loss of generality.

For each candidate A, the group order #E and the twist order #Eᵗ were computed. A candidate was admissible when:

- A² − 4 is a quadratic non-residue modulo p;
- #E = 4 · n and #Eᵗ = 4 · nᵗ with n and nᵗ prime;
- A − 2 is a quadratic residue (equivalently A + 2 is a non-residue), so the dual Edwards model E_{d,a} is complete.

The first admissible value is A = **61370**. The scan is reproduced by `tool/find_A.sage`. The generator G is then fixed by the djb / RFC 7748 rule, adapted to cofactor 4: the smallest x ≥ 1 whose point has order n, taking the even y root.

This is a first-hit selection, not a uniqueness claim over the whole range. Earlier drafts reported A = 479597 as the unique admissible coefficient in 0 ≤ A ≤ 10⁶; that uniqueness claim was incorrect, because A = 61370 is an earlier admissible coefficient under the same criteria. This version uses the first hit of the deterministic scan.

### Resulting Parameters

| Parameter | Value |
|---|---|
| Prime p | 2²⁵⁶ − 189 |
| Coefficient A | 61370 |
| Cofactor h | 4 |
| Twist cofactor | 4 |
| A² − 4 mod p | 3766276896 (non-square) |

The full parameter set, including the subgroup orders n and nᵗ and the generator G, is listed under [Curve Parameters](#curve-parameters).

---

## Curve Parameters

| Parameter | Value                                                                            |
|---|----------------------------------------------------------------------------------|
| **Equation** | y² = x³ + Ax² + x                                                                |
| **Prime p** | 2²⁵⁶ − 189                                                                        |
| **Coefficient A** | 61370                                                                            |
| **Subgroup order n** | 28948022309329048855892746252171976963404671476872247083542990644359122995957    |
| **Cofactor h** | 4                                                                                |
| **Twist order** | 4 × 28948022309329048855892746252171976963230320855948034936185801359597441823917 |
| **Generator Gx** | 6                                                                                |
| **Generator Gy** | 34517194831513652290546734430452415224722876045332401153182996255764394237320     |

**Breaking change:** the coefficient is `A = 61370`. Keys, signatures, and shared secrets produced with the earlier draft value `A = 479597` are not compatible with this parameter set.

---

## Components

| Component | Description |
| --- | --- |
| **Curve256189** | Montgomery curve: core arithmetic, point validation, scalar blinding |
| **Ed256189** | EdDSA signatures on the complete dual curve E_{d,a}: 33-byte public keys, 65-byte signatures, SHA-512, strict verification |
| **Edwards** | Twisted Edwards form E_{a,d}, with addition evaluated on the dual complete curve E_{d,a} |
| **DualEdwards** | Complete Edwards model E_{d,a} with the standard exception-free addition law and 33-byte point encoding |
| **X256189** | ECDH key exchange with cofactor clearing per RFC 7748 |
| **XEdDSA** | x-only Schnorr-style signatures on the Montgomery curve (**superseded** by Ed256189; kept for compatibility) |
| **Elligator 2** | Point encoding and decoding per RFC 9380 |
| **HKDF** | Key derivation per RFC 5869 |
| **AES-GCM** | Authenticated encryption per NIST SP 800-38D |
| **Batch Verify** | Batch verification of XEdDSA and Ed256189 signatures with strict per-input validation (multi-scalar multiplication is not yet optimised) |

---

## SafeCurves Compliance

Curve256189 satisfies all 11 SafeCurves criteria, verified with SageMath:

| # | Criterion | Detail | Status |
| --- | --- | --- | --- |
| 1 | Field | p = 2²⁵⁶ - 189 = 115792089237316195423570985008687907853269984665640564039457584007913129639747 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43 (prime, nearest form with c=189 < 2¹²⁸) | Pass |
| 2 | Equation | y² = x³ + 61370x² + x, B(A²-4) mod p = 3766276896 ≠ 0 | Pass |
| 3 | Base Point | G = (6, 34517194831513652290546734430452415224722876045332401153182996255764394237320), n = 28948022309329048855892746252171976963404671476872247083542990644359122995957 = 0x4000000000000000000000000000000041955aa52f59439b1a47b190eedd4af5 (prime), n·G = ∞ | Pass |
| 4 | Rho | 0.886·√n ≈ 2¹²⁶·⁸ > 2¹⁰⁰ | Pass |
| 5 | Transfer | n ≠ p, and there is no embedding degree k ≤ 1000 (k > 1000); additive and multiplicative transfer are not applicable at practical sizes | Pass |
| 6 | Discriminant | Trace t = -348701241848424294714378569523362344080, \|D\| = 85393950220657872762888265174989618040708991235949662744802537447685051878147 = 0xbccb4355e64bf786d2fb98098d7e7abecc3bd5d0265bf025a12de1f8f7278b03 ≈ 2²⁵⁵·⁵⁶ > 2¹⁰⁰ | Pass |
| 7 | Rigidity | A = 61370 is the first hit of a deterministic scan from 0 with cofactors (4, 4), prime subgroup order, prime twist subgroup order, A²-4 non-square, and a complete dual Edwards model (A-2 square); reproduced by `tool/find_A.sage` | Pass |
| 8 | Ladder | A²-4 mod p = 3766276896 (non-square) | Pass |
| 9 | Twist | Twist order = 115792089237316195423570985008687907852921283423792139744743205438389767295668 = 0xfffffffffffffffffffffffffffffffef9aa956b429af19396e139bc448ad2b4, twist cofactor = 4, twist subgroup order = 28948022309329048855892746252171976963230320855948034936185801359597441823917 (prime) | Pass |
| 10 | Completeness | Montgomery ladder complete (A²-4 non-square); the affine twisted Edwards layer uses the dual curve E_{d,a}, whose standard addition law is complete because a' = d = 61368 is a square and d' = a = 61372 is a non-square | Pass |
| 11 | Indistinguishability | Elligator 2 applicable: A²-4 non-square, curve has a point of order 2 | Pass |

**Total: 11/11 criteria met.**

Full verification: `tool/safecurves_curve256189.sage`

---

## Edwards Representation and Completeness

Curve256189 has two birationally equivalent twisted Edwards models:

| Model | Equation | Coefficients | Addition law |
|---|---|---|---|
| Natural (`E_{a,d}`) | `a x² + y² = 1 + d x² y²` | `a = A + 2 = 61372`, `d = A − 2 = 61368` | Incomplete |
| Dual (`E_{d,a}`) | `d u² + v² = 1 + a u² v²` | `a' = d = 61368`, `d' = a = 61372` | Complete |

Modulo `p`, the coefficient `a` is a quadratic non-residue and `d` is a quadratic residue, so the natural model is outside the Bernstein–Lange completeness condition. Its two points of order 4 lie at infinity in the affine `(x, y)` chart, and the standard addition law fails when the difference of the inputs is one of them, or when their sum is one of them.

Swapping the coefficients fixes this. On `E_{d,a}` the coefficient of `u²` is a square and the coefficient of `u²v²` is a non-square, exactly the condition under which the standard addition law is complete. The curves are isomorphic through

```
Phi(x, y) = (-x, 1/y) : E_{a,d} -> E_{d,a},
Phi(P + Q) = Phi(P) + Phi(Q),
```

and `Phi` is an involution. `TwistedEdwards.add` therefore computes `Phi(Phi(P) + Phi(Q))` using the complete law on `E_{d,a}`. This removes the old exceptional cases: every pair whose difference is an order-4 point now adds correctly.

This is different from adding a second "dual" addition formula on `E_{a,d}` itself: completeness comes from moving to the isomorphic curve `E_{d,a}` and using its ordinary addition law, which has no exceptional inputs there. Alternative unified formulas on `E_{a,d}` (for example the Hisil–Wong–Carter–Dawson formulas) still have exceptional cases and are not used here.

The only result that cannot be represented is a sum that is itself one of the two order-4 points of `E_{a,d}`. Those points have no affine `(x, y)` coordinates, so `TwistedEdwards.add` raises a `StateError` instead of returning a bogus point. The Montgomery layer and `DualEdwards` still handle them natively.

`DualEdwards` exposes the complete model directly, with `fromMontgomery` / `toMontgomery`, `fromTwistedEdwards` / `toTwistedEdwards`, `isOnCurve`, `add`, `negate`, `scalarMul`, `encodePoint`, `decodePoint`, and `isInPrimeOrderSubgroup`. It is also the signature curve for Ed256189; see [doc/ed256189.md](doc/ed256189.md).

---

## Security Properties

- **Montgomery ladder:** scalar multiplication runs a fixed number of iterations and uses an arithmetic conditional swap instead of branching on the secret bit.
- **Scalar blinding:** randomized 64-bit multiples of the full curve order `4n` via `Random.secure()`, which preserves the result for every curve point and reduces timing leakage.
- **Point validation:** rejects the point at infinity, out-of-range coordinates, off-curve points, and low-order points.
- **Cofactor clearing:** h = 4, following the RFC 7748 convention.
- **Ed256189 signatures:** deterministic nonce from a secret prefix and the message, domain-separated nonce and challenge, canonical `S < n`, exact 65-byte signatures, canonical 33-byte point encodings, prime-order subgroup membership for both `R` and `A`, and the exact group equation `[S]B == R + [k]A`. Low-order and mixed-order keys are rejected.
- **XEdDSA signatures (superseded):** strict verification with canonical `s < n`, exact 64-byte signatures, canonical even-`y` decoding, and prime-order subgroup membership for both `R` and `P`.
- **Independent keys:** Ed256189 derives its key on `E_{d,a}` without the `×4` cofactor clearing used by X256189/XEdDSA, so the same seed gives unrelated keys across the schemes.
- **Non-malleable signatures:** canonical scalars, subgroup checks, and exact point equality reject sign-flipped `R`, `s + n`, and low-order components.
- **Elligator 2:** uniform random-looking point encoding, providing resistance to traffic analysis.
- **Complete Edwards addition:** affine Edwards addition is evaluated on the dual curve `E_{d,a}`, whose standard addition law is complete. The only rejected result is an order-4 sum that has no affine representation.

### Side-Channel Considerations

The implementation relies on Dart's `BigInt`, whose arithmetic is not guaranteed to run in constant time. The ladder structure and scalar blinding reduce timing leakage, but they do not constitute a formal constant-time guarantee. Deployments with strong side-channel requirements should account for this.

---

## Test Vectors

### Ed256189
```
Seed:       000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Public Key: d9d17d95f9d83184c44697bfcca1cab7bdda20c9d6aade29ce7c4dffe495443e01
Message:    (empty)
Signature:  341616287279b7aefee0324944cfcdb23a087f2fa8b7653cd465886661317b2c
            009a43064c25e56cf1d837bf1a79d32830aed4f40d9b8bfe1936c799e80f668c0b
```
```
Seed:       000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Public Key: d9d17d95f9d83184c44697bfcca1cab7bdda20c9d6aade29ce7c4dffe495443e01
Message:    "abc" (616263)
Signature:  f9f76423b996bf12ad4bfb42dbfc00bc599fadcde5c0fe95a34e52f43005fb7e
            0125589599f718b7080b4934032370053e9fb636dff0e1110cba01cd9052220620
```

The public key is a 33-byte encoded point on `E_{d,a}` and the signature is
`R || S` (33 + 32 bytes). Ed256189 is **not** wire-compatible with Ed25519,
Ed448, or XEdDSA. The full 16-vector set is generated by
`tool/ed256189_vectors.py` and checked in `test/eddsa256189_test.dart`; see
[doc/ed256189.md](doc/ed256189.md).

### XEdDSA (superseded)
```
Seed:       0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Public Key: b1b998018648e7195a06c1b8c6bd029c84d384be33673c010f83a960a1160275
Message:    "Hello Curve256189!"
Signature:  3f09322f361f003a7e0478f44c3d095a91e6bd5b3e55f5c806d57325a665b5f6
            0e0659fb94c480fd0b1daa30d9e32118288a1e53acf2d872a80e53195311fc09
```

The public key is identical to the X256189 key for the same seed, because both
derive the cofactor-cleared scalar. The signature is `x(R) || s`, both
little-endian 32-byte values. XEdDSA is **not** wire-compatible with RFC 8032
EdDSA, and the same seed produces a different Ed256189 key. XEdDSA is
**superseded** by Ed256189; keep it only for existing data and protocols.

### X256189 (ECDH + HKDF)
```
Alice Seed: 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Alice PK:   b1b998018648e7195a06c1b8c6bd029c84d384be33673c010f83a960a1160275
Bob Seed:   2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
Bob PK:     62bd3d3f9ccf01644be90c04884effff0e1198187a6d11731a9b53ff0bf0467c
Shared:     49dc0d93c74668da52553c6d981e60996b7bc9fae0930bedcc3e4e67bf57da86
HKDF key:   a9bc7c6d77c1bb62f0193dc1f2267285a90fd58316a933fc79c2122e474ab3c0
```

### Elligator 2
```
encode(1)  = 38597363079105398474523661669562635951089994888546854679819194669304376505669
encode(2)  = 51463150772140531299364882226083514601453326518062472906425592892405835340892
encode(42) = 53318828282980679388864508540413105769782863440540072701648788328948380688035
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

### Ed256189: EdDSA Sign and Verify
```dart
import 'package:curve256189/curve256189.dart';
import 'dart:typed_data';

// Generate key pair from a 32-byte seed.
final seed = Uint8List(32); // use a cryptographically random seed
final keyPair = Ed256189.generateKeyPair(seed);

// Sign (deterministic, 65-byte signature).
final message = Uint8List.fromList('Hello!'.codeUnits);
final signature = Ed256189.sign(message, keyPair['privateKey']!);

// Verify.
final valid = Ed256189.verify(message, signature, keyPair['publicKey']!);
```

The public key is 33 bytes and the signature is 65 bytes (`R || S`). The
scheme is specified in [doc/ed256189.md](doc/ed256189.md) and is not
wire-compatible with Ed25519, Ed448, or XEdDSA. Ed256189 keys are independent
of X256189/XEdDSA keys derived from the same seed.

Batch verification uses the same 33-byte public keys and 65-byte signatures.
Every entry is validated with the same parser as individual verification:

```dart
final ok = Ed256189BatchVerify.verify([
  Ed256189SignatureBundle(
    message: message,
    signature: signature,
    publicKey: keyPair['publicKey']!,
  ),
]);
```

As with XEdDSA, multi-scalar multiplication is currently a loop of independent
scalar multiplications, so the batch verifier is primarily a validation-
consistency API, not yet a throughput win.

### XEdDSA: Sign and Verify (superseded)
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

// Derive the public key without generating the full key pair
final publicKey = XEdDSA.publicKeyFromSeed(seed);
```

XEdDSA is specified in [doc/xeddsa.md](doc/xeddsa.md). It is an x-only
Montgomery profile, not a wire-compatible implementation of Signal XEdDSA.
Its public keys are identical to X256189 keys derived from the same seed.

Batch verification uses the same 64-byte signatures and 32-byte public keys.
Every entry is validated with the same parser as individual verification. Note
that multi-scalar multiplication is currently a loop of independent scalar
multiplications, so batch verification is not yet faster than verifying the
same signatures individually:

```dart
final ok = BatchVerify.verify([
  SignatureBundle(
    message: message,
    signature: signature,
    publicKey: keyPair['publicKey']!,
  ),
]);
```

### Edwards: complete affine addition
```dart
import 'package:curve256189/curve256189.dart';

final g = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);
final twoG = TwistedEdwards.scalarMul(BigInt.two, g);

// Exception-free for affine points, including doubling and mixed orders.
final threeG = TwistedEdwards.add(g, twoG);

// Or work directly on the complete dual model E_{d,a}.
final gDual = DualEdwards.fromMontgomery(MontgomeryPoint.G);
final threeGDual = DualEdwards.scalarMul(BigInt.from(3), gDual);
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
dart pub get
dart test                  # full suite
dart test -x slow          # skip the randomised and long-running tests
dart test test/xeddsa_test.dart
```

| File | Covers |
|---|---|
| `test/field_test.dart` | field arithmetic, `pow` regression for structured inputs |
| `test/params_test.dart` | curve constants, orders, twist, embedding degree |
| `test/montgomery_test.dart` | group law, ladder, blinding, point validation |
| `test/edwards_test.dart` | birational maps, dual-curve completeness, group law, point compression |
| `test/eddsa256189_test.dart` | Ed256189 vectors, point encoding, subgroup validation, malformed signatures and keys |
| `test/eddsa256189_batch_test.dart` | Ed256189 batch versus individual agreement, malformed entries, scale and stability |
| `test/elligator_test.dart` | test vectors, RFC 9380 exceptional case, decode |
| `test/x256189_test.dart` | ECDH vectors, invalid and twist public keys |
| `test/xeddsa_test.dart` | independent vectors, anchor regression, malleability, invalid inputs, protocol separation |
| `test/xeddsa_vectors.dart` | generated XEdDSA known-answer vectors (do not edit by hand) |
| `test/batch_verify_test.dart` | batch versus individual agreement, malformed entries, scale and stability |
| `test/hkdf_test.dart` | RFC 5869 vectors |
| `test/aesgcm_test.dart` | NIST vectors, tamper and AAD checks |
| `test/stress_test.dart` | randomised checks (tag `slow`) |

Analysis and benchmark scripts live in `tool/` and are not part of the test
suite:

```bash
sage tool/safecurves_curve256189.sage
sage tool/find_prime.sage
dart run tool/twist_analysis.dart
dart run tool/mov_analysis.dart
dart run tool/benchmark.dart
dart run tool/benchmark_e2e.dart
python tool/xeddsa_vectors.py --dart test/xeddsa_vectors.dart
python tool/ed256189_vectors.py --dart test/ed256189_vectors.dart
```

---

## Implementation Notes

- **No `BigInt.modPow`:** Dart's `BigInt.modPow` returns wrong results for some structured 256-bit inputs, for example base `p - 1` or `(p - 1) / 2` (2253 of 5904 structured cases failed on one Dart SDK). Random inputs rarely trigger it. All modular exponentiation therefore uses the square-and-multiply implementation in `FieldElement.pow()`, which `test/field_test.dart` checks against known answers on structured and random inputs. Every exponent used in the library is a public constant, so branching on its bits does not leak secrets.
- **Okeya-Sakurai y-recovery:** `Montgomery.scalarMulFull` uses the Okeya-Sakurai (2001) formula to recover a full point from the x-only ladder. The `[k+1]P = O` case is handled directly, and a double-and-add fallback covers any remaining degenerate input. Scalar blinding adds a random 64-bit multiple of `4n`, so it is correct for low-order and mixed-order points as well.
- **Dual-curve Edwards addition:** the natural form `E_{a,d}` has a non-square `a` and a square `d`, so its standard addition law is incomplete. `TwistedEdwards.add` maps to the dual curve `E_{d,a}` through `Phi(x, y) = (-x, 1/y)`, adds with the complete law there, and maps back. Only a sum equal to an order-4 point, which has no affine coordinates, is rejected.
- **Ed256189 signature curve:** RFC 8032 requires a square `a` and a non-square `d`. Curve256189's natural model has the opposite, so Ed256189 uses `E_{d,a}` and the generator `B = Phi(G)`. Because `p` is a full 256-bit prime there is no spare sign bit, so points are encoded as `LE(v, 32) || parity(u)` (33 bytes). `S < n < 2^255` is encoded in 32 bytes, giving 65-byte signatures.
- **Ed256189 key derivation:** `SHA-512(seed)` is split into a 32-byte scalar and a 32-byte prefix. The scalar is pruned for cofactor 4 (clear bits 0–1, clear bit 255, set bit 254), not reduced modulo `n`, and not multiplied by 4. Keys are therefore independent of X256189/XEdDSA keys for the same seed.
- **Ed256189 nonce and challenge:** `r = SHA-512("Curve256189-Ed256189-v1" || 0x01 || prefix || counter || M) mod n` (4-byte little-endian counter, retried only if `r = 0`), and `k = SHA-512(domain || 0x02 || R || A || M) mod n`. Both hashes cover the domain string and tag explicitly.
- **Ed256189 verification:** exact 33-byte public-key and 65-byte signature lengths, canonical `S < n`, canonical point encodings, non-identity prime-order subgroup checks for both `R` and `A`, and the exact equation `[S]B == R + [k]A`. Signatures are deterministic and non-malleable; malformed inputs return `false` instead of throwing.
- **x-only signatures (XEdDSA, superseded):** XEdDSA avoids Edwards addition entirely. Signing and verification canonicalise `P` and `R` to the even-`y` representative and check the exact full-point equation `[s]G == R + [h]P`, so variants such as `(x(R), n - s)` or a sign-flipped `R` cannot be accepted.
- **XEdDSA strict validation:** signatures must be exactly 64 bytes, `s < n`, and both `R` and `P` must decode to canonical even-`y` points in the prime-order subgroup. Low-order and mixed-order public keys are rejected.
- **Parity byte handling:** `TwistedEdwards.decodePoint` tests `(bytes[32] & 1) == 1` rather than `bytes[32] == 1`, so all odd parity byte values are decoded correctly. `DualEdwards.decodePoint`, used by Ed256189, is stricter and rejects any parity byte other than `0` or `1`.
- **Little-endian encoding:** all byte serialization follows the RFC 7748 convention.
- **XEdDSA nonce and challenge:** `SHA-512(domain || 0x01 || prefix || counter || message) mod n` and `SHA-512(domain || 0x02 || x(R) || x(P) || message) mod n`.

### Ed256189 Scheme Summary

| Item | Value |
|---|---|
| Signature curve | `E_{d,a}: d·u² + v² = 1 + a·u²·v²`, `a' = 61368`, `d' = 61372` |
| Generator | `B = Phi(G)` on `E_{d,a}` |
| Domain separation | `Curve256189-Ed256189-v1`, tags `0x01` (nonce) and `0x02` (challenge) |
| Secret derivation | `s = LE(SHA-512(seed)[0..32])` pruned for cofactor 4 |
| Public key | `enc([s]B)`, 33 bytes |
| Nonce | `r = SHA-512(domain ‖ 0x01 ‖ prefix ‖ counter ‖ M) mod n` |
| Challenge | `k = SHA-512(domain ‖ 0x02 ‖ R ‖ A ‖ M) mod n` |
| Signature | `R ‖ S`, 65 bytes, `S = r + k·s mod n` |
| Verification | `[S]B == R + [k]A` after subgroup checks |

Full specification and deviation list: [doc/ed256189.md](doc/ed256189.md).

### XEdDSA Scheme Summary (superseded)

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
security-critical system. **XEdDSA is superseded by Ed256189** and is kept
only for compatibility; new protocols should use Ed256189.

---

## License

MIT License. See [LICENSE](LICENSE).

---

## References

### Curve and Edwards arithmetic
- [SafeCurves](https://safecurves.cr.yp.to/)
- [SafeCurves: Completeness](https://safecurves.cr.yp.to/complete.html)
- [Bernstein–Lange, *Twisted Edwards Curves* (2008)](https://eprint.iacr.org/2008/013)
- [Bernstein–Lange, *A complete set of addition laws for incomplete Edwards curves* (2009)](https://eprint.iacr.org/2009/580)
- [Hisil–Wong–Carter–Dawson, *Twisted Edwards Curves Revisited* (2008)](https://eprint.iacr.org/2008/522)
- [Edwards, *A normal form for elliptic curves* (2007)](https://www.ams.org/journals/bull/2007-44-03/S0273-0979-07-01153-6/)

### Protocols and primitives
- [Ed256189 specification](doc/ed256189.md): parameters, wire format, and deviations from RFC 8032
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748): Elliptic Curves for Diffie-Hellman
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Edwards-Curve Digital Signature Algorithm
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380): Hashing to Elliptic Curves (Elligator 2)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869): HKDF
- [Signal XEdDSA specification](https://signal.org/docs/specifications/xeddsa/)
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final): AES-GCM

---

**Last updated:** 2026-11-10
