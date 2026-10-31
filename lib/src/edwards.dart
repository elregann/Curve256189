// edwards.dart

import 'dart:typed_data';
import 'field.dart';
import 'montgomery.dart';
import 'params.dart';

class EdwardsPoint {
  final BigInt x;
  final BigInt y;
  final bool isInfinity;

  EdwardsPoint(this.x, this.y) : isInfinity = false;

  // Neutral point (0, 1) as the identity element in Twisted Edwards
  EdwardsPoint.infinity()
      : x = BigInt.zero,
        y = BigInt.one,
        isInfinity = false;

  bool get isIdentity => x == BigInt.zero && y == BigInt.one;
}

class TwistedEdwards {
  static final BigInt p = Curve256189Params.p;
  static final BigInt A = Curve256189Params.A;

  // Twisted Edwards coefficient: a = A + 2
  static final BigInt a = FieldElement.add(A, BigInt.two);

  // Twisted Edwards coefficient d
  static final BigInt d = Curve256189Params.d;

  // ---------------------------------------------------------------------
  // Birational maps
  // ---------------------------------------------------------------------

  // Montgomery (x, y) -> Twisted Edwards (u, v) = (x/y, (x-1)/(x+1)).
  // The map is undefined at the order-2 point (0, 0) and at the order-4
  // points with x = -1. The order-2 point is mapped explicitly; order-4
  // points are genuinely exceptional for this chart and throw.
  static EdwardsPoint fromMontgomery(MontgomeryPoint P) {
    if (P.isInfinity) return EdwardsPoint.infinity();

    if (P.y == BigInt.zero) {
      // Only (0, 0) has y = 0 on this curve; it maps to (0, -1).
      if (P.x == BigInt.zero) {
        return EdwardsPoint(
            BigInt.zero, FieldElement.sub(BigInt.zero, BigInt.one));
      }
      throw ArgumentError('invalid Montgomery point with y = 0');
    }

    if (P.x == FieldElement.sub(BigInt.zero, BigInt.one)) {
      throw StateError(
        'order-4 Montgomery point is exceptional for the Edwards chart',
      );
    }

    final u = FieldElement.mul(P.x, FieldElement.inv(P.y));
    final v = FieldElement.mul(
      FieldElement.sub(P.x, BigInt.one),
      FieldElement.inv(FieldElement.add(P.x, BigInt.one)),
    );

    return EdwardsPoint(u, v);
  }

  // Twisted Edwards (u, v) -> Montgomery (x, y) = ((1+v)/(1-v), x/u).
  static MontgomeryPoint toMontgomery(EdwardsPoint P) {
    if (P.isIdentity) return MontgomeryPoint.infinity();

    if (P.x == BigInt.zero) {
      // (0, -1) is the order-2 point; it maps to Montgomery (0, 0).
      if (P.y == FieldElement.sub(BigInt.zero, BigInt.one)) {
        return MontgomeryPoint(BigInt.zero, BigInt.zero);
      }
      throw ArgumentError('invalid Edwards point with x = 0');
    }

    final oneMinusV = FieldElement.sub(BigInt.one, P.y);
    if (oneMinusV == BigInt.zero) {
      throw StateError('Edwards point with v = 1 is exceptional');
    }

    final x = FieldElement.mul(
      FieldElement.add(BigInt.one, P.y),
      FieldElement.inv(oneMinusV),
    );
    final y = FieldElement.mul(x, FieldElement.inv(P.x));

    return MontgomeryPoint(x, y);
  }

  // Point validation: ax² + y² = 1 + dx²y²
  static bool isOnCurve(EdwardsPoint P) {
    final x2 = FieldElement.mul(P.x, P.x);
    final y2 = FieldElement.mul(P.y, P.y);

    final left = FieldElement.add(FieldElement.mul(a, x2), y2);
    final right = FieldElement.add(
      BigInt.one,
      FieldElement.mul(d, FieldElement.mul(x2, y2)),
    );

    return left == right;
  }

  // ---------------------------------------------------------------------
  // Group law
  // ---------------------------------------------------------------------

  // Twisted Edwards point addition.
  //
  // Note: this curve does not satisfy the completeness condition for the
  // twisted Edwards addition law. The exceptional inputs (points of order 4)
  // are rejected explicitly instead of silently producing invalid results.
  static EdwardsPoint add(EdwardsPoint P, EdwardsPoint Q) {
    if (P.isIdentity) return Q;
    if (Q.isIdentity) return P;

    final x1 = P.x;
    final y1 = P.y;
    final x2 = Q.x;
    final y2 = Q.y;

    final x1y2 = FieldElement.mul(x1, y2);
    final y1x2 = FieldElement.mul(y1, x2);
    final y1y2 = FieldElement.mul(y1, y2);
    final x1x2 = FieldElement.mul(x1, x2);
    final x1x2y1y2 = FieldElement.mul(x1x2, y1y2);
    final dx1x2y1y2 = FieldElement.mul(d, x1x2y1y2);

    final denX = FieldElement.add(BigInt.one, dx1x2y1y2);
    final denY = FieldElement.sub(BigInt.one, dx1x2y1y2);
    if (denX == BigInt.zero || denY == BigInt.zero) {
      throw StateError(
        'TwistedEdwards.add is incomplete for this input '
        '(points of order 4)',
      );
    }

    // x3 = (x1y2 + y1x2) / (1 + dx1x2y1y2)
    final x3 = FieldElement.mul(
      FieldElement.add(x1y2, y1x2),
      FieldElement.inv(denX),
    );

    // y3 = (y1y2 - a*x1x2) / (1 - dx1x2y1y2)
    final y3 = FieldElement.mul(
      FieldElement.sub(y1y2, FieldElement.mul(a, x1x2)),
      FieldElement.inv(denY),
    );

    return EdwardsPoint(x3, y3);
  }

  static EdwardsPoint negate(EdwardsPoint P) {
    if (P.isIdentity) return EdwardsPoint.infinity();
    return EdwardsPoint(FieldElement.sub(BigInt.zero, P.x), P.y);
  }

  // Scalar multiplication routed through full-point Montgomery arithmetic.
  static EdwardsPoint scalarMul(BigInt k, EdwardsPoint P) {
    if (k == BigInt.zero || P.isIdentity) return EdwardsPoint.infinity();
    if (k < BigInt.zero) {
      return scalarMul(-k, negate(P));
    }

    final montP = toMontgomery(P);
    if (montP.isInfinity) return EdwardsPoint.infinity();

    final result = Montgomery.scalarMulFull(k, montP);
    if (result.isInfinity) return EdwardsPoint.infinity();
    return fromMontgomery(result);
  }

  // ---------------------------------------------------------------------
  // Point compression: 32 bytes Y || 1 byte X-parity
  // ---------------------------------------------------------------------

  static Uint8List encodePoint(EdwardsPoint P) {
    final yBytes = _bigIntToBytes(P.y);
    final signByte = P.x.isOdd ? 1 : 0;
    return Uint8List.fromList([...yBytes, signByte]);
  }

  // Point decompression: recovery of X from compressed Y and parity.
  // Returns null for malformed encodings.
  static EdwardsPoint? decodePoint(Uint8List bytes) {
    if (bytes.length != 33) return null;

    final signX = (bytes[32] & 1) == 1;
    final yBytes = bytes.sublist(0, 32);

    final y = _bytesToBigInt(yBytes);
    if (y >= p) return null;

    // x² = (1 - y²) / (a - dy²)
    final y2 = FieldElement.mul(y, y);
    final numerator = FieldElement.sub(BigInt.one, y2);
    final denominator = FieldElement.sub(a, FieldElement.mul(d, y2));
    if (denominator == BigInt.zero) return null;

    final x2 = FieldElement.mul(numerator, FieldElement.inv(denominator));

    // Square root: x = x²^((p+1)/4)
    final exp = (p + BigInt.one) >> 2;
    var x = FieldElement.pow(x2, exp);

    if (FieldElement.mul(x, x) != x2) return null;

    // Sign selection based on decoded parity
    if (x != BigInt.zero && x.isOdd != signX) {
      x = FieldElement.sub(BigInt.zero, x);
    }

    final point = EdwardsPoint(x, y);
    if (!isOnCurve(point)) return null;
    return point;
  }

  // Little-endian BigInt to Byte array conversion (32 bytes)
  static Uint8List _bigIntToBytes(BigInt value) {
    final bytes = Uint8List(32);
    var v = value;
    for (int i = 0; i < 32; i++) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }

  // Little-endian Byte array to BigInt conversion
  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = result | (BigInt.from(bytes[i]) << (8 * i));
    }
    return result;
  }
}
