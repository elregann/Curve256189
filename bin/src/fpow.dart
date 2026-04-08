// fpow.dart

// FPOW — Fixed-Point One-Way Wrap
// Curve256189 Research — March 2026
// Ismael Urzaiz Aranda, Tangerang Selatan
//
// Discovered as an evolution of the HFE scalar obfuscation layer.
// The original HFE pipeline (S∘F∘T) was found recoverable via
// Lagrange interpolation with only degree+1 known-plaintext pairs.
//
// FPOW replaces polynomial transformation with a hash-based
// fixed-point construction:
//
//   wrap(k, secret) = k + H(secret ‖ k) mod n
//   where H = SHA-512 (one-way function)
//
// Properties verified via SageMath (fpow_curve256189.sage):
//   ✅ Non-polynomial — Lagrange interpolation fails
//   ✅ Statistical uniformity — output ratio ~1.0
//   ✅ Differential randomness — unique diffs per input
//   ✅ Fixed-point one-way equation:
//      k_raw = k_wrapped − H(secret ‖ k_raw) mod n
//      → circular dependency → brute force 2^256
//   ✅ Quantum resistance — Grover: 2^128 (infeasible)
//
// Shor resistance analysis:
//   Shor's algorithm on ECDLP → recovers k_wrapped
//   k_wrapped ≠ k_raw — attacker cannot sign or decrypt
//   Recovery requires solving fixed-point SHA-512 equation
//   → No known algebraic shortcut exists
//
// Note: This is a novel construction not found in surveyed
// literature at time of writing. Kept as research contribution
// pending formal peer review.
import 'dart:typed_data';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'params.dart';

class FPOW {
  static final BigInt n = Curve256189Params.n;

  // Domain separation tag — prevents cross-protocol attacks
  static final List<int> _domain = utf8.encode('Curve256189-FPOW-v1');

  // H(secret ‖ k) — deterministic hash mixing
  // Uses double SHA-512 for 1024-bit internal state
  // Output reduced mod n for uniform distribution
  //
  // Why kBytes appears in both h1 and h2:
  // h1 = SHA-512(secret ‖ k) — binds secret and k together
  // h2 = SHA-512(h1 ‖ k)     — strengthens k-dependence
  //      kBytes in h2 ensures output depends directly on k
  //      even if h1 propagation is somehow weakened.
  //      This is "double binding" — k influences output
  //      through two independent hash paths.
  static BigInt _computeH(Uint8List secret, BigInt k) {
    final kBytes = _bigIntToBytes(k);
    final h1 = sha512.convert([...secret, ...kBytes]).bytes;
    final h2 = sha512.convert([...h1, ...kBytes]).bytes;
    return _bytesToBigInt(Uint8List.fromList([...h1, ...h2])) % n;
  }

  // Fixed-Point One-Way Wrap
  // k_wrapped = k_raw + H(secret ‖ k_raw) mod n
  //
  // Properties:
  // - Deterministic: same k + secret → same k_wrapped
  // - One-way: k_wrapped → k_raw requires solving fixed-point equation
  // - Non-polynomial: not recoverable via Lagrange interpolation
  // - Output in range [0, n)
  static BigInt wrap(BigInt k, Uint8List secret) {
    return (k + _computeH(secret, k)) % n;
  }

  // Derive secret from seed via SHA-256 + domain separation
  // secret = SHA-256(seed ‖ domain)
  // Domain separation ensures FPOW secret is independent
  // from other key material derived from the same seed
  static Uint8List deriveSecret(Uint8List seed) {
    return Uint8List.fromList(
      sha256.convert([...seed, ..._domain]).bytes,
    );
  }

  // Convert BigInt to 32-byte big-endian array
  // Big-endian is used intentionally for hash input —
  // this is an internal function for H computation only.
  // Note: differs from EdDSA/X256189 which use little-endian
  // per RFC 7748/8032. These are separate domains:
  // FPOW hash input (big-endian) vs wire format (little-endian).
  static Uint8List _bigIntToBytes(BigInt value) {
    final bytes = Uint8List(32);
    var v = value;
    for (int i = 31; i >= 0; i--) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }

  // Convert byte array to BigInt
  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }
}