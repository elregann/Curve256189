import 'params.dart';

class FieldElement {
  static final BigInt p = Curve256189Params.p;

  // Modular addition
  static BigInt add(BigInt a, BigInt b) {
    return (a + b) % p;
  }

  // Modular subtraction
  static BigInt sub(BigInt a, BigInt b) {
    return ((a - b) % p + p) % p;
  }

  // Modular multiplication
  static BigInt mul(BigInt a, BigInt b) {
    return (a * b) % p;
  }

  // Modular inverse (Fermat's little theorem)
  // a^(p-2) mod p
  static BigInt inv(BigInt a) {
    return a.modPow(p - BigInt.two, p);
  }

  // Modular exponentiation
  static BigInt pow(BigInt a, BigInt exp) {
    return a.modPow(exp, p);
  }
}