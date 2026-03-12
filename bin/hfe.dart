// Jacques Patarin — 1996
// HFE (Hidden Field Equations)

// ECDLP — problem name
// Elliptic Curve Discrete Logarithm Problem

// hfe.dart
import 'params.dart';
import 'dart:typed_data';
import 'dart:convert';
import 'package:crypto/crypto.dart';

class HFE {
  static final BigInt n = Curve256189Params.n;

  // Degree polynomial F
  static final BigInt e = BigInt.from(3);

  // Transformasi S: x → (a*x + b) mod n
  static BigInt _applyS(BigInt x, BigInt a, BigInt b) {
    return ((a * x) + b) % n;
  }

  // Polynomial F: X^3 + coeff*X mod n
  static BigInt _applyF(BigInt x, BigInt coeff) {
    return (x.modPow(e, n) + coeff * x) % n;
  }

  // Transformasi T: x → (c*x + d) mod n
  static BigInt _applyT(BigInt x, BigInt c, BigInt d) {
    return ((c * x) + d) % n;
  }

  // Full pipeline: k → S → F → T → k'
  static BigInt wrap(BigInt k, BigInt a, BigInt b, BigInt c, BigInt d, BigInt coeff) {
    final sk = _applyS(k, a, b);
    final fsk = _applyF(sk, coeff);
    return _applyT(fsk, c, d);
  }

  // Derive HFE constants dari seed
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
      'a': extract(0, 12),
      'b': extract(12, 24),
      'c': extract(24, 36),
      'd': extract(36, 48),
      'coeff': extract(48, 60),
    };
  }
}