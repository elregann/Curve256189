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
}

class TwistedEdwards {
  static final BigInt p = Curve256189Params.p;
  static final BigInt A = Curve256189Params.A;

  // Twisted Edwards coefficient: a = A + 2
  static final BigInt a = FieldElement.add(A, BigInt.two);

  // Twisted Edwards coefficient: d = A - 2
  static final BigInt d = FieldElement.sub(A, BigInt.two);

  // Birational Map: Montgomery (x, y) to Twisted Edwards (u, v)
  static EdwardsPoint fromMontgomery(MontgomeryPoint P) {
    if (P.isInfinity) return EdwardsPoint.infinity();

    // Mapping: u = x / y
    final u = FieldElement.mul(P.x, FieldElement.inv(P.y));

    // Mapping: v = (x - 1) / (x + 1)
    final v = FieldElement.mul(
      FieldElement.sub(P.x, BigInt.one),
      FieldElement.inv(FieldElement.add(P.x, BigInt.one)),
    );

    return EdwardsPoint(u, v);
  }

  // Birational Map: Twisted Edwards (u, v) to Montgomery (x, y)
  static MontgomeryPoint toMontgomery(EdwardsPoint P) {
    if (P.x == BigInt.zero && P.y == BigInt.one) return MontgomeryPoint.infinity();

    // Mapping: x = (1 + v) / (1 - v)
    final x = FieldElement.mul(
      FieldElement.add(BigInt.one, P.y),
      FieldElement.inv(FieldElement.sub(BigInt.one, P.y)),
    );

    // Mapping: y = x / u
    final y = FieldElement.mul(x, FieldElement.inv(P.x));

    return MontgomeryPoint(x, y);
  }

  // Point validation: ax² + y² = 1 + dx²y²
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

  // Twisted Edwards point addition formula
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

    // Result x: x3 = (x1y2 + y1x2) / (1 + dx1x2y1y2)
    final x3 = FieldElement.mul(
      FieldElement.add(x1y2, y1x2),
      FieldElement.inv(FieldElement.add(BigInt.one, dx1x2y1y2)),
    );

    // Result y: y3 = (y1y2 - ax1x2) / (1 - dx1x2y1y2)
    final y3 = FieldElement.mul(
      FieldElement.sub(y1y2, FieldElement.mul(a, x1x2)),
      FieldElement.inv(FieldElement.sub(BigInt.one, dx1x2y1y2)),
    );

    return EdwardsPoint(x3, y3);
  }

  // Standard scalar multiplication (interface for Montgomery Ladder conversion)
  static EdwardsPoint scalarMul(BigInt k, EdwardsPoint P) {
    if (k == BigInt.zero) return EdwardsPoint.infinity();

    // Edwards → Montgomery
    final montP = toMontgomery(P);

    // Montgomery Ladder x-only (complete + constant-time)
    final xR = Montgomery.ladderXOnly(k, montP.x);
    if (xR == BigInt.zero) return EdwardsPoint.infinity();

    // Recover y dari y² = x³ + Ax² + x
    final x2 = FieldElement.mul(xR, xR);
    final x3 = FieldElement.mul(xR, x2);
    final rhs = FieldElement.add(
      FieldElement.add(x3, FieldElement.mul(A, x2)),
      xR,
    );
    final exp = (p + BigInt.one) >> 2;
    var yR = FieldElement.pow(rhs, exp);

    if (FieldElement.mul(yR, yR) != rhs) {
      return _scalarMulFallback(k, P);
    }

    // Canonical y: choose even
    if (yR.isOdd) yR = FieldElement.sub(BigInt.zero, yR);

    // Montgomery → Edwards
    return fromMontgomery(MontgomeryPoint(xR, yR));
  }

  // Double-and-Add implementation for fallback/verification
  static EdwardsPoint _scalarMulFallback(BigInt k, EdwardsPoint P) {
    EdwardsPoint r0 = EdwardsPoint.infinity();
    EdwardsPoint r1 = P;
    final bitLength = k.bitLength;
    for (int i = bitLength - 1; i >= 0; i--) {
      final bit = (k >> i) & BigInt.one;
      if (bit == BigInt.zero) {
        r1 = add(r0, r1);
        r0 = add(r0, r0);
      } else {
        r0 = add(r0, r1);
        r1 = add(r1, r1);
      }
    }
    return r0;
  }

  // Point compression: 32 bytes Y + 1 byte X-parity
  static Uint8List encodePoint(EdwardsPoint P) {
    final yBytes = _bigIntToBytes(P.y);
    final signByte = P.x.isOdd ? 1 : 0;
    return Uint8List.fromList([...yBytes, signByte]);
  }

  // Point decompression: Recovery of X from compressed Y and parity
  static EdwardsPoint? decodePoint(Uint8List bytes) {
    if (bytes.length != 33) return null;

    final signX = bytes[32] == 1;
    final yBytes = bytes.sublist(0, 32);

    final y = _bytesToBigInt(yBytes);
    if (y >= p) return null;

    // x² = (1 - y²) / (a - dy²)
    final y2 = FieldElement.mul(y, y);
    final numerator = FieldElement.sub(BigInt.one, y2);
    final denominator = FieldElement.sub(
      a,
      FieldElement.mul(d, y2),
    );
    final x2 = FieldElement.mul(numerator, FieldElement.inv(denominator));

    // Square root: x = x²^((p+1)/4)
    final exp = (p + BigInt.one) >> 2;
    var x = FieldElement.pow(x2, exp);

    if (FieldElement.mul(x, x) != x2) return null;

    // Sign selection based on decoded parity
    if (x.isOdd != signX) {
      x = FieldElement.sub(BigInt.zero, x);
    }

    return EdwardsPoint(x, y);
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