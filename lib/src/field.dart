// field.dart

import 'params.dart';

class FieldElement {
  // Prime field modulus p from curve parameters
  static final BigInt p = Curve256189Params.p;

  // Modular addition (a + b) mod p
  static BigInt add(BigInt a, BigInt b) {
    return (a + b) % p;
  }

  // Modular subtraction (a - b) mod p with underflow protection
  static BigInt sub(BigInt a, BigInt b) {
    return ((a - b) % p + p) % p;
  }

  // Modular multiplication (a * b) mod p
  static BigInt mul(BigInt a, BigInt b) {
    return (a * b) % p;
  }

  // Modular inversion via Extended Euclidean Algorithm.
  // Throws instead of silently returning 0 for the undefined inverse of 0.
  static BigInt inv(BigInt a) {
    final value = ((a % p) + p) % p;
    if (value == BigInt.zero) {
      throw ArgumentError('FieldElement.inv(0) is undefined modulo p');
    }

    BigInt oldR = value, r = p;
    BigInt oldS = BigInt.one, s = BigInt.zero;
    while (r != BigInt.zero) {
      final q = oldR ~/ r;
      final tempR = r;
      r = oldR - q * r;
      oldR = tempR;
      final tempS = s;
      s = oldS - q * s;
      oldS = tempS;
    }
    return ((oldS % p) + p) % p;
  }

  // Modular exponentiation a^exp mod p via Dart's BigInt.modPow.
  // Every exponent used in this library is a public constant, so the
  // non constant time behaviour of modPow does not leak secrets here.
  static BigInt pow(BigInt a, BigInt exp) {
    if (exp < BigInt.zero) {
      throw ArgumentError('FieldElement.pow requires a non-negative exponent');
    }
    return (a % p).modPow(exp, p);
  }

  // Modular inversion with inv0(0) = 0 per RFC 9380
  static BigInt inv0(BigInt a) {
    if (a == BigInt.zero) return BigInt.zero;
    return inv(a);
  }
}
