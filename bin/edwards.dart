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

  // Point compression — encode titik ke 32 bytes (simpan y + 1 bit paritas x)
  static Uint8List encodePoint(EdwardsPoint P) {
    final yBytes = _bigIntToBytes(P.y);
    // Simpan paritas x di bit tertinggi byte terakhir
    if (P.x.isOdd) {
      yBytes[31] |= 0x80;
    }
    return yBytes;
  }

  // Point decompression — recover titik dari 32 bytes
  static EdwardsPoint? decodePoint(Uint8List bytes) {
    final compressed = Uint8List.fromList(bytes);

    // Ambil bit paritas x dari bit tertinggi
    final signX = (compressed[31] & 0x80) != 0;
    compressed[31] &= 0x7f; // hapus bit paritas

    final y = _bytesToBigInt(compressed);
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

  // Helper — BigInt ke bytes little-endian 32 bytes
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
    for (int i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }
}