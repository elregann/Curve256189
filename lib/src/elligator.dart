// elligator.dart

import 'field.dart';
import 'params.dart';

class Elligator {
  static final BigInt p = Curve256189Params.p;
  static final BigInt A = Curve256189Params.A;

  // Non-square constant u = 2 (smallest non-square mod p)
  static final BigInt u = BigInt.two;

  // Elligator 2 encode: field element t → Montgomery x
  // Maps uniform random field element to curve point x-coordinate
  // Returns null if t == 0
  static BigInt? encode(BigInt t) {
    if (t == BigInt.zero) return null;

    // x1 = -A / (1 + u*t²)
    final t2 = FieldElement.mul(t, t);
    final denom = FieldElement.add(BigInt.one, FieldElement.mul(u, t2));

    final x1 = FieldElement.mul(
      FieldElement.sub(BigInt.zero, A),
      FieldElement.inv0(denom),
    );
    // x2 = -x1 - A
    final x2 = FieldElement.sub(FieldElement.sub(BigInt.zero, x1), A);

    // Select x which lies on curve: y² = x³ + Ax² + x
    final rhs1 = _curveRhs(x1);
    final exp = (p + BigInt.one) >> 2;
    final y1 = rhs1.modPow(exp, p);
    if (FieldElement.mul(y1, y1) == rhs1) return x1;
    return x2;
  }

  static BigInt? decode(BigInt x) {
    // t² = -(x + A) / (u * x)
    final num = FieldElement.sub(BigInt.zero, FieldElement.add(x, A));
    final den = FieldElement.mul(u, x);
    if (den == BigInt.zero) return null;

    final t2 = FieldElement.mul(num, FieldElement.inv(den));

    // Square root: t = t²^((p+1)/4) — use safe impl due to Dart modPow bug
    final exp = (p + BigInt.one) >> 2;
    final t = _modPowSafe(t2, exp, p);

    // Verify t is valid square root
    if (FieldElement.mul(t, t) != t2) return null;

    // Canonical form: return smaller of t and p-t
    final tNeg = FieldElement.sub(BigInt.zero, t);
    final half = p >> 1;
    return t <= half ? t : tNeg;
  }

  // Safe modular exponentiation — replaces Dart BigInt.modPow
  // due to precision issues with 256-bit numbers
  static BigInt _modPowSafe(BigInt base, BigInt exp, BigInt mod) {
    BigInt result = BigInt.one;
    base = base % mod;
    while (exp > BigInt.zero) {
      if (exp.isOdd) result = (result * base) % mod;
      exp = exp >> 1;
      base = (base * base) % mod;
    }
    return result;
  }

  // Montgomery curve RHS: x³ + Ax² + x
  static BigInt _curveRhs(BigInt x) {
    final x2 = FieldElement.mul(x, x);
    final x3 = FieldElement.mul(x, x2);
    return FieldElement.add(
      FieldElement.add(x3, FieldElement.mul(A, x2)),
      x,
    );
  }
}