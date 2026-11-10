## 1.0.0-beta.6

- **Breaking: Curve256189 now uses `A = 61370`.** The Montgomery coefficient
  moved from the earlier draft value `A = 479597` to the first admissible value
  of a deterministic scan from 0. Keys, signatures and shared secrets produced
  with `A = 479597` are not compatible with this parameter set.
- The selection is a *first-hit* rule, not a uniqueness claim. Earlier drafts
  described `A = 479597` as the unique admissible coefficient in
  `0 <= A <= 10^6`; that claim was incorrect, because `A = 61370` is an earlier
  admissible coefficient under the same criteria. `tool/find_A.sage` reproduces
  the scan.
- Updated parameters: `a24 = 15343`, `aEd = 61372`, `d = 61368`, `gx = 6`, and
  the derived base points. `n` now satisfies `2^254 < n < 2^255` and `#E = 4n`
  is 257 bits; the twist subgroup order is 254 bits. Both subgroup orders remain
  prime and both cofactors remain 4.
- Regenerated all Ed256189 and XEdDSA test vectors and both independent Python
  generators. `tool/safecurves_curve256189.sage` now checks the first-hit rule
  and dual-curve completeness.
- **Added `example/`** with runnable examples for Ed256189, X256189 ECDH,
  XEdDSA (superseded), AES-256-GCM and Elligator 2, plus a complete
  ECDH -> HKDF -> AES-GCM workflow. The directory follows the Pub `example/`
  convention.
- **Added `SECURITY.md`** documenting the non-constant-time `BigInt` caveat, the
  absence of an independent audit, and the supported version line.
- CI now enforces `dart format`, runs every example, and validates the package
  with `dart pub publish --dry-run`.
- `pubspec.lock` and IDE metadata are no longer tracked; `.pubignore` keeps them
  out of the published package.
- Documentation now states `S < n < 2^255` for Ed256189 signatures (the previous
  `2^254` bound applied to the old parameter set).

## 1.0.0-beta.5

- **New `Ed256189` signature scheme.** EdDSA for Curve256189 on the complete
  dual twisted Edwards model `E_{d,a}`. RFC 8032 requires a square `a` and a
  non-square `d`; Curve256189's natural model has the opposite, so Ed256189
  uses the isomorphic dual model and the generator `B = Phi(G)`. Public keys
  are 33 bytes (`LE(v, 32) || parity(u)`) and signatures are 65 bytes
  (`R || S`) because `p` is a full 256-bit prime and `S < n < 2^254`.
- Ed256189 key derivation follows RFC 8032: `SHA-512(seed)`, split into a
  32-byte scalar and a 32-byte prefix, with cofactor-4 pruning (clear bits
  0–1, clear bit 255, set bit 254). The scalar is not reduced modulo `n`
  and not multiplied by 4, so Ed256189 keys are independent of X256189 and
  XEdDSA keys derived from the same seed.
- Ed256189 signing uses a deterministic, domain-separated nonce
  `SHA-512("Curve256189-Ed256189-v1" || 0x01 || prefix || counter || M) mod n`
  with a 4-byte little-endian counter retried only if `r = 0`, and a
  domain-separated challenge
  `SHA-512(domain || 0x02 || R || A || M) mod n`. The signature scalar is
  `S = r + k*s mod n`.
- Ed256189 verification is strict: exact lengths, canonical point encodings,
  canonical `S < n`, non-identity prime-order subgroup checks for both `R`
  and `A`, and the exact equation `[S]B == R + [k]A` (no cofactor
  multiplication). Malformed inputs return `false` and never throw.
- **Added `DualEdwards` encoding helpers:** `encodePoint`, `decodePoint`
  (33-byte `v || parity(u)`, rejecting `v >= p`, parity bytes other than
  0/1, non-square `u²`, and an odd parity for `u = 0`), and
  `isInPrimeOrderSubgroup` (rejects identity, order-2, order-4, and
  mixed-order points). `DualEdwards.scalarMul` gained an optional `blind`
  flag for secret scalars.
- **Added an independent Python reference and vector generator:**
  `tool/ed256189_vectors.py`, which shares no code with the Dart package and
  emits 16 known-answer vectors (4 seeds × 4 messages) to
  `test/ed256189_vectors.dart`. The Dart implementation matches all of them.
- **Added tests:** `test/eddsa256189_test.dart` covers the parameter set,
  generator, point encoding and decoding edge cases, subgroup validation, key
  derivation, all vectors, determinism, malformed signatures and keys, and
  protocol separation from XEdDSA. Randomised Ed256189 and `DualEdwards`
  round-trips were added to `test/stress_test.dart` (tag `slow`).
- **Added `doc/ed256189.md`:** full specification of the parameters, wire
  format, key derivation, nonce and challenge, signing, verification, edge
  cases, security notes, and every deliberate deviation from RFC 8032
  (including the 33/65-byte formats, `b = 264` point encoding, 32-byte `S`,
  SHA-512 output size, explicit domain tags, nonce counter retry, strict
  non-cofactored verification, and the absent ctx/ph variants).
- **`XEdDSA` is now marked superseded** by Ed256189. Its behaviour, wire
  format, test vectors, and `BatchVerify` are unchanged in this release; it
  will be removed in a future major release. Ed256189 and XEdDSA are not
  wire-compatible and do not share keys.
- Docs: README updated with the Ed256189 component, security properties,
  usage example, vectors, scheme summary, test file, and RFC 8032 reference.
- Version bumped to `1.0.0-beta.5`.

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