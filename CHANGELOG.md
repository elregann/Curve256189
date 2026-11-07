## 1.0.0-beta.4

- Edwards: added `DualEdwards`, the complete twisted Edwards model
  `E_{d,a}: d u² + v² = 1 + a u² v²`. For Curve256189, `a' = d` is a square
  and `d' = a` is a non-square, so its standard addition law has no exceptional
  cases.
- Edwards: `TwistedEdwards.add` now evaluates the sum on `E_{d,a}` through the
  involution `Phi(x, y) = (-x, 1/y)` and maps back. This fixes the incomplete
  addition law on the natural model `E_{a,d}`, including pairs whose difference
  is an order-4 point. A sum that is itself one of the two order-4 points has
  no affine coordinates and is reported with a `StateError` instead of a bogus
  result.
- Tests: added dual-curve completeness checks, map round-trips (including
  order-2 and order-4 points), the previously failing difference-of-order-4
  cases, the non-representable order-4 sum, and a randomised mixed-order
  comparison against Montgomery arithmetic.
- Docs: documented the Edwards/dual-curve construction and added Edwards
  completeness references (Bernstein–Lange, Hisil et al., SafeCurves).
- Tests: replaced the print-based scripts in `dev/` with a real `package:test`
  suite in `test/` (`dart test`). Every check is an assertion, known answers
  were computed independently in Python, and randomised checks are tagged
  `slow`. Added RFC 5869 (HKDF) and NIST (AES-GCM) vectors, malformed-input
  cases for XEdDSA and batch verification, twist and mixed-order public key
  rejection, and Edwards point compression edge cases.
- Analysis and benchmark scripts moved to `tool/`.
- Added GitHub Actions CI (`dart analyze`, `dart test`) and stopped tracking
  `.idea/`, `*.iml` and `pubspec.lock`.
- Elligator 2 `encode` now follows RFC 9380 section 6.7.1 when
  `1 + 2t² = 0`: `x1` is set to `-A` instead of `0`, so the two affected
  inputs no longer map to the order-2 point. `decode` maps `x = -A` back to
  the matching `t`.
- `FieldElement.pow` keeps its own square and multiply implementation because
  Dart's `BigInt.modPow` returns wrong results for some structured inputs
  (for example base `p - 1`). `Elligator` now reuses `FieldElement.pow` and
  `Montgomery.curveRhs` instead of private duplicates. `test/field_test.dart`
  covers structured inputs with known answers.
- Removed the FPOW claim from the changelog and package metadata. It is not
  part of this library.

## 1.0.0-beta.3

- Hardened the Montgomery ladder with an arithmetic conditional swap and a
  fixed iteration count, removing bit-dependent branches from the scalar
  multiplication loop.
- Increased scalar blinding entropy from 32 to 64 bits and fixed the blinded
  ladder length so its execution length does not depend on the scalar's bit
  length.
- Handle `[k+1]P = O` directly, keeping the secret-dependent double-and-add
  fallback off the normal scalar multiplication path.

## 1.0.0-beta.2

- **Breaking:** replaced the EdDSA implementation with **XEdDSA**, an x-only
  Schnorr-style signature scheme on the Montgomery curve.
- Public keys are now 32-byte x-only values; signatures are 64 bytes
  (`x(R) || s`). The wire format is not compatible with the previous release.
- Signing and verification use only Montgomery arithmetic and the exact
  full-point equation `[s]G == R + [h]P`; no Edwards addition is involved.
- Verification and batch verification strictly reject non-canonical `s`,
  malformed lengths, low-order points, mixed-order public keys, and
  non-prime-order `R`/`P`.
- `XEdDSA.generateKeyPair(seed)` now produces the same public key as
  `X256189.generateKeyPair(seed)`.
- Hardened point decoding, scalar multiplication (Okeya-Sakurai y-recovery
  with fallback), scalar blinding over the full curve order, and
  `FieldElement.inv(0)` error handling.
- Updated the `XEdDSA` example, test vectors, and test suite
  (`test/xeddsa_test.dart`).

## 1.0.0-beta.1

- Initial release of Curve256189.
- Verified SafeCurves compliance (11/11 criteria).
- Support for ECDH (X256189) and EdDSA signatures.
- Elligator 2 point encoding and HKDF integration.