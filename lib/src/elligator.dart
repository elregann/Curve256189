// elligator.dart

import 'field.dart';
import 'montgomery.dart';
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

    var x1 = FieldElement.mul(
      FieldElement.sub(BigInt.zero, A),
      FieldElement.inv0(denom),
    );
    // RFC 9380 section 6.7.1: when 1 + u*t² == 0, x1 is defined as -A
    if (x1 == BigInt.zero) x1 = FieldElement.sub(BigInt.zero, A);
    // x2 = -x1 - A
    final x2 = FieldElement.sub(FieldElement.sub(BigInt.zero, x1), A);

    // Select x which lies on curve: y² = x³ + Ax² + x
    final rhs1 = Montgomery.curveRhs(x1);
    final exp = (p + BigInt.one) >> 2;
    final y1 = FieldElement.pow(rhs1, exp);
    if (FieldElement.mul(y1, y1) == rhs1) return x1;
    return x2;
  }

  static BigInt? decode(BigInt x) {
    final BigInt t2;
    if (x == FieldElement.sub(BigInt.zero, A)) {
      // Exceptional point reached from 1 + u*t² == 0, so t² = -1 / u
      t2 = FieldElement.sub(BigInt.zero, FieldElement.inv(u));
    } else {
      // t² = -(x + A) / (u * x)
      final num = FieldElement.sub(BigInt.zero, FieldElement.add(x, A));
      final den = FieldElement.mul(u, x);
      if (den == BigInt.zero) return null;
      t2 = FieldElement.mul(num, FieldElement.inv(den));
    }

    // Square root: t = t²^((p+1)/4)
    final exp = (p + BigInt.one) >> 2;
    final t = FieldElement.pow(t2, exp);

    // Verify t is valid square root
    if (FieldElement.mul(t, t) != t2) return null;

    // Canonical form: return smaller of t and p-t
    final tNeg = FieldElement.sub(BigInt.zero, t);
    final half = p >> 1;
    return t <= half ? t : tNeg;
  }
}
