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

  // Modular exponentiation a^exp mod p via square and multiply.
  // Dart's BigInt.modPow returns wrong results for some 256 bit inputs, for
  // example base p minus 1 or (p minus 1) / 2, so it must not be used here.
  // See test/field_test.dart. Every exponent used in this library
  // is a public constant, so branching on its bits does not leak secrets.
  static BigInt pow(BigInt a, BigInt exp) {
    if (exp < BigInt.zero) {
      throw ArgumentError('FieldElement.pow requires a non-negative exponent');
    }
    BigInt result = BigInt.one;
    BigInt base = a % p;
    BigInt e = exp;
    while (e > BigInt.zero) {
      if (e.isOdd) result = (result * base) % p;
      e = e >> 1;
      base = (base * base) % p;
    }
    return result;
  }

  // Modular inversion with inv0(0) = 0 per RFC 9380
  static BigInt inv0(BigInt a) {
    if (a == BigInt.zero) return BigInt.zero;
    return inv(a);
  }
}
