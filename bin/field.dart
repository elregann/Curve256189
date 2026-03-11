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

  // Modular inversion via Fermat's Little Theorem: a^(p-2) mod p
  static BigInt inv(BigInt a) {
    return a.modPow(p - BigInt.two, p);
  }

  // Modular exponentiation a^exp mod p
  static BigInt pow(BigInt a, BigInt exp) {
    return a.modPow(exp, p);
  }
}