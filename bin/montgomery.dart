import 'field.dart';
import 'params.dart';

class MontgomeryPoint {
  final BigInt x;
  final BigInt y;
  final bool isInfinity;

  const MontgomeryPoint(this.x, this.y) : isInfinity = false;
  MontgomeryPoint.infinity()
      : x = BigInt.zero,
        y = BigInt.zero,
        isInfinity = true;

  // Base point G
  static final MontgomeryPoint G = MontgomeryPoint(
    Curve256189Params.gx,
    Curve256189Params.gy,
  );
}

class Montgomery {
  static final BigInt p = Curve256189Params.p;
  static final BigInt A = Curve256189Params.A;

  // Cek apakah titik valid di kurva
  // y² = x³ + Ax² + x (mod p)
  static bool isOnCurve(MontgomeryPoint point) {
    if (point.isInfinity) return true;
    final x = point.x;
    final y = point.y;
    final left = FieldElement.mul(y, y);
    final right = FieldElement.add(
      FieldElement.add(
        FieldElement.mul(x, FieldElement.mul(x, x)),
        FieldElement.mul(A, FieldElement.mul(x, x)),
      ),
      x,
    );
    return left == right;
  }

  // Point addition
  static MontgomeryPoint add(MontgomeryPoint P, MontgomeryPoint Q) {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;
    if (P.x == Q.x) {
      if (P.y != Q.y) return MontgomeryPoint.infinity();
      return double_(P);
    }

    // lambda = (y2 - y1) / (x2 - x1)
    final dy = FieldElement.sub(Q.y, P.y);
    final dx = FieldElement.sub(Q.x, P.x);
    final lambda = FieldElement.mul(dy, FieldElement.inv(dx));

    // x3 = lambda² - A - x1 - x2
    final x3 = FieldElement.sub(
      FieldElement.sub(
        FieldElement.sub(FieldElement.mul(lambda, lambda), A),
        P.x,
      ),
      Q.x,
    );

    // y3 = lambda(x1 - x3) - y1
    final y3 = FieldElement.sub(
      FieldElement.mul(lambda, FieldElement.sub(P.x, x3)),
      P.y,
    );

    return MontgomeryPoint(x3, y3);
  }

  // Point doubling
  static MontgomeryPoint double_(MontgomeryPoint P) {
    if (P.isInfinity) return P;

    // lambda = (3x² + 2Ax + 1) / (2y)
    final x2 = FieldElement.mul(P.x, P.x);
    final numerator = FieldElement.add(
      FieldElement.add(
        FieldElement.mul(BigInt.from(3), x2),
        FieldElement.mul(BigInt.two * A, P.x),
      ),
      BigInt.one,
    );
    final denominator = FieldElement.mul(BigInt.two, P.y);
    final lambda = FieldElement.mul(numerator, FieldElement.inv(denominator));

    // x3 = lambda² - A - 2x
    final x3 = FieldElement.sub(
      FieldElement.sub(FieldElement.mul(lambda, lambda), A),
      FieldElement.mul(BigInt.two, P.x),
    );

    // y3 = lambda(x - x3) - y
    final y3 = FieldElement.sub(
      FieldElement.mul(lambda, FieldElement.sub(P.x, x3)),
      P.y,
    );

    return MontgomeryPoint(x3, y3);
  }

  // Scalar multiplication (double-and-add)
  static MontgomeryPoint scalarMul(BigInt k, MontgomeryPoint P) {
    MontgomeryPoint result = MontgomeryPoint.infinity();
    MontgomeryPoint addend = P;

    while (k > BigInt.zero) {
      if (k.isOdd) {
        result = add(result, addend);
      }
      addend = double_(addend);
      k = k >> 1;
    }

    return result;
  }
}