// hfe.dart

// Scalar obfuscation layer — HFE-inspired pipeline
// Jacques Patarin, 1996.
//
// ⚠️  RESEARCH NOTE (March 2026):
// This implementation was found to be recoverable
// via Lagrange interpolation with only degree+1
// known-plaintext pairs. See fpow.dart for the
// evolved implementation (FPOW) that addresses
// this weakness.
//
// This file is kept for historical reference and
// to document the research journey that led to
// the discovery of FPOW.

import 'params.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'package:crypto/crypto.dart';

class HFE {
  static final BigInt n = Curve256189Params.n;

  // Polynomial degree e=3 — safe for Dart BigInt.modPow
  static final BigInt e = BigInt.from(3);

  // Affine transformation S: x → (a*x + b) mod n
  // All operations in Z/nZ — NOT GF(p)
  static BigInt _applyS(BigInt x, BigInt a, BigInt b) {
    return ((a * x) + b) % n;
  }

  // Polynomial transformation F: x^3 + coeff*x mod n
  // modPow safe here — e=3 is a small constant exponent
  static BigInt _applyF(BigInt x, BigInt coeff) {
    return (x.modPow(e, n) + coeff * x) % n;
  }

  // Affine transformation T: x → (c*x + d) mod n
  static BigInt _applyT(BigInt x, BigInt c, BigInt d) {
    return ((c * x) + d) % n;
  }

  // Full obfuscation pipeline: k → S → F → T → k'
  // Input k must be in range [0, n)
  // Output k' guaranteed in range [0, n)
  static BigInt wrap(BigInt k, BigInt a, BigInt b, BigInt c, BigInt d, BigInt coeff) {
    final sk = _applyS(k, a, b);
    final fsk = _applyF(sk, coeff);
    return _applyT(fsk, c, d);
  }

  // Derive obfuscation constants from seed via SHA-512
  // Constants deterministic — same seed always produces same constants
  // Each constant in range [2, n) to avoid degenerate cases
  static Map<String, BigInt> deriveConstants(Uint8List seed) {
    final input = Uint8List.fromList([...seed, ...utf8.encode('Curve256189-HFE-v1')]);
    final h = sha512.convert(input).bytes;

    BigInt extract(int start, int end) {
      BigInt result = BigInt.zero;
      for (int i = start; i < end; i++) {
        result = (result << 8) | BigInt.from(h[i]);
      }
      return (result % (n - BigInt.two)) + BigInt.two;
    }

    return {
      'a':     extract(0,  12),  // S coefficient
      'b':     extract(12, 24),  // S constant
      'c':     extract(24, 36),  // T coefficient
      'd':     extract(36, 48),  // T constant
      'coeff': extract(48, 60),  // F polynomial coefficient
    };
  }
}