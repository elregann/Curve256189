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
  (`dev/unit/test_xeddsa.dart`).

## 1.0.0-beta.1

- Initial release of Curve256189.
- Verified SafeCurves compliance (11/11 criteria).
- Implementation of FPOW (Fixed-Point One-Way Wrap) for scalar hardening.
- Support for ECDH (X256189) and EdDSA signatures.
- Elligator 2 point encoding and HKDF integration.