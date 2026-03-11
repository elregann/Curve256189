import 'field.dart';
import 'montgomery.dart';
import 'params.dart';

class EdwardsPoint {
  final BigInt x;
  final BigInt y;
  final bool isInfinity;

  EdwardsPoint(this.x, this.y) : isInfinity = false;
  EdwardsPoint.infinity()
      : x = BigInt.zero,
        y = BigInt.one,
        isInfinity = false;
// Di Twisted Edwards, titik netral adalah (0, 1) bukan infinity!
}

class TwistedEdwards {
  static final BigInt p = Curve256189Params.p;
  static final BigInt A = Curve256189Params.A;

  // a = A + 2
  static final BigInt a = FieldElement.add(A, BigInt.two);

  // d = A - 2
  static final BigInt d = FieldElement.sub(A, BigInt.two);

  // Konversi Montgomery (x, y) → Twisted Edwards (u, v)
  static EdwardsPoint fromMontgomery(MontgomeryPoint P) {
    if (P.isInfinity) return EdwardsPoint.infinity();

    // u = x / y
    final u = FieldElement.mul(P.x, FieldElement.inv(P.y));

    // v = (x - 1) / (x + 1)
    final v = FieldElement.mul(
      FieldElement.sub(P.x, BigInt.one),
      FieldElement.inv(FieldElement.add(P.x, BigInt.one)),
    );

    return EdwardsPoint(u, v);
  }

  // Cek apakah titik valid di Twisted Edwards
  // ax² + y² = 1 + dx²y²
  static bool isOnCurve(EdwardsPoint P) {
    final x2 = FieldElement.mul(P.x, P.x);
    final y2 = FieldElement.mul(P.y, P.y);

    final left = FieldElement.add(
      FieldElement.mul(a, x2),
      y2,
    );

    final right = FieldElement.add(
      BigInt.one,
      FieldElement.mul(d, FieldElement.mul(x2, y2)),
    );

    return left == right;
  }

  // Point addition Twisted Edwards
  // (x1,y1) + (x2,y2) = ((x1y2 + y1x2) / (1 + dx1x2y1y2),
  //                       (y1y2 - ax1x2) / (1 - dx1x2y1y2))
  static EdwardsPoint add(EdwardsPoint P, EdwardsPoint Q) {
    final x1 = P.x;
    final y1 = P.y;
    final x2 = Q.x;
    final y2 = Q.y;

    final x1y2 = FieldElement.mul(x1, y2);
    final y1x2 = FieldElement.mul(y1, x2);
    final y1y2 = FieldElement.mul(y1, y2);
    final x1x2 = FieldElement.mul(x1, x2);
    final x1x2y1y2 = FieldElement.mul(x1x2, FieldElement.mul(y1, y2));
    final dx1x2y1y2 = FieldElement.mul(d, x1x2y1y2);

    // x3 = (x1y2 + y1x2) / (1 + dx1x2y1y2)
    final x3 = FieldElement.mul(
      FieldElement.add(x1y2, y1x2),
      FieldElement.inv(FieldElement.add(BigInt.one, dx1x2y1y2)),
    );

    // y3 = (y1y2 - ax1x2) / (1 - dx1x2y1y2)
    final y3 = FieldElement.mul(
      FieldElement.sub(y1y2, FieldElement.mul(a, x1x2)),
      FieldElement.inv(FieldElement.sub(BigInt.one, dx1x2y1y2)),
    );

    return EdwardsPoint(x3, y3);
  }

  // Scalar multiplication
  static EdwardsPoint scalarMul(BigInt k, EdwardsPoint P) {
    EdwardsPoint result = EdwardsPoint.infinity();
    EdwardsPoint addend = P;

    while (k > BigInt.zero) {
      if (k.isOdd) {
        result = add(result, addend);
      }
      addend = add(addend, addend);
      k = k >> 1;
    }

    return result;
  }
}