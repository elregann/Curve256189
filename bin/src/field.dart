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

  // Modular inversion via Extended Euclidean Algorithm
  // Note: Dart BigInt.modPow has precision issues for 256-bit numbers
  static BigInt inv(BigInt a) {
    BigInt oldR = a, r = p;
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

  // Safe modular exponentiation via square-and-multiply
  // Replaces Dart BigInt.modPow due to precision issues with 256-bit numbers
  static BigInt pow(BigInt a, BigInt exp) {
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