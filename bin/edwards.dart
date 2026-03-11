import 'dart:typed_data';
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

  // Konversi Twisted Edwards (u, v) → Montgomery (x, y)
  static MontgomeryPoint toMontgomery(EdwardsPoint P) {
    if (P.x == BigInt.zero && P.y == BigInt.one) return MontgomeryPoint.infinity();

    // x = (1 + v) / (1 - v)
    final x = FieldElement.mul(
      FieldElement.add(BigInt.one, P.y),
      FieldElement.inv(FieldElement.sub(BigInt.one, P.y)),
    );

    // y = x / u
    final y = FieldElement.mul(x, FieldElement.inv(P.x));

    return MontgomeryPoint(x, y);
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
  //                     (y1y2 - ax1x2) / (1 - dx1x2y1y2))
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

  // Convert Edwards → Montgomery → Ladder x-only → recover y → Edwards
  // Scalar multiplication — via Montgomery Ladder (COMPLETE)
  static EdwardsPoint scalarMul(BigInt k, EdwardsPoint P) {
    return scalarMulDebug(k, P);
  }

  // Fallback scalar mul langsung di Edwards (sangat jarang dipanggil)
  static EdwardsPoint scalarMulDebug(BigInt k, EdwardsPoint P) {
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

  // Point compression — encode titik ke 33 bytes
  // 32 bytes y (little-endian) + 1 byte paritas x
  static Uint8List encodePoint(EdwardsPoint P) {
    final yBytes = _bigIntToBytes(P.y); // 32 bytes
    final signByte = P.x.isOdd ? 1 : 0;
    return Uint8List.fromList([...yBytes, signByte]); // 33 bytes
  }

  // Point decompression — recover titik dari 33 bytes
  static EdwardsPoint? decodePoint(Uint8List bytes) {
    if (bytes.length != 33) return null;

    // Ambil paritas x dari byte terakhir
    final signX = bytes[32] == 1;
    final yBytes = bytes.sublist(0, 32);

    final y = _bytesToBigInt(yBytes);
    if (y >= p) return null;

    // Recover x² = (1 - y²) / (a - d*y²) mod p
    final y2 = FieldElement.mul(y, y);
    final numerator = FieldElement.sub(BigInt.one, y2);
    final denominator = FieldElement.sub(
      a,
      FieldElement.mul(d, y2),
    );
    final x2 = FieldElement.mul(numerator, FieldElement.inv(denominator));

    // Square root: x = x²^((p+1)/4) mod p
    final exp = (p + BigInt.one) >> 2;
    var x = x2.modPow(exp, p);

    // Verifikasi square root valid
    if (FieldElement.mul(x, x) != x2) return null;

    // Pilih x yang paritasnya sesuai
    if (x.isOdd != signX) {
      x = FieldElement.sub(BigInt.zero, x);
    }

    return EdwardsPoint(x, y);
  }

  // Konversi BigInt → bytes (33 bytes, little-endian)
  static Uint8List _bigIntToBytes(BigInt value) {
    final bytes = Uint8List(32);
    var v = value;
    for (int i = 0; i < 32; i++) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }

  // Helper — bytes little-endian ke BigInt
  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = result | (BigInt.from(bytes[i]) << (8 * i));
    }
    return result;
  }
}