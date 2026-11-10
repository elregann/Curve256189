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
  // E_{a,d} is not one of the twisted Edwards curves for which the standard
  // addition law is complete. Its two order-4 points lie at infinity in this
  // affine chart, and the formula fails when the difference of the inputs is
  // one of them (the old implementation rejected those sums), or when their
  // sum is one of them (that sum has no affine result).
  //
  // We therefore evaluate the sum on the dual curve E_{d,a}, where the
  // standard addition law is complete, using the group isomorphism
  //
  //     Phi(x, y) = (-x, 1/y) : E_{a,d} -> E_{d,a}.
  //
  // Since Phi is an involution,
  //
  //     P + Q = Phi( Phi(P) + Phi(Q) ).
  //
  // The only case that cannot be represented in this affine chart is when the
  // true sum is one of the two order-4 points: those have no affine (x, y)
  // coordinates on E_{a,d}, so the final map back reports it explicitly.
  static EdwardsPoint add(EdwardsPoint P, EdwardsPoint Q) {
    if (P.isIdentity) return Q;
    if (Q.isIdentity) return P;

    final dualSum = DualEdwards.add(
      DualEdwards.fromTwistedEdwards(P),
      DualEdwards.fromTwistedEdwards(Q),
    );
    return DualEdwards.toTwistedEdwards(dualSum);
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

// Complete twisted Edwards layer for Curve256189.
//
// The natural Edwards form of Curve256189 is
//
//     E_{a,d}: a x² + y² = 1 + d x² y²,
//     a = A + 2 = 61372,  d = A - 2 = 61368.
//
// Here a is a quadratic non-residue and d is a quadratic residue, so the
// standard addition law on E_{a,d} is incomplete: it fails when the difference
// of the inputs is one of the two order-4 points (they are at infinity in the
// affine chart), and when their sum is one of them.
//
// Swapping the coefficients gives the dual curve
//
//     E_{d,a}: d u² + v² = 1 + a u² v².
//
// On E_{d,a} the coefficient of u² is d (a square) and the coefficient of
// u²v² is a (a non-square). This is exactly the Bernstein-Lange completeness
// condition, so the standard addition law is complete on E_{d,a}.
//
// The two curves are isomorphic through the involution
//
//     Phi(x, y) = (-x, 1/y) : E_{a,d} -> E_{d,a},
//
// which fixes the identity and satisfies
//
//     Phi(P + Q) = Phi(P) + Phi(Q).
//
// TwistedEdwards.add uses this map, so its only unrepresentable result is a sum
// that is itself an order-4 point of E_{a,d}.
//
// Points in this class use EdwardsPoint with (x, y) interpreted as the dual
// coordinates (u, v).
class DualEdwards {
  static final BigInt p = Curve256189Params.p;

  // Coefficient of x² on E_{d,a}: a' = d (a quadratic residue).
  static final BigInt a = TwistedEdwards.d;

  // Coefficient of x²y² on E_{d,a}: d' = a (a quadratic non-residue).
  static final BigInt d = TwistedEdwards.a;

  // ---------------------------------------------------------------------
  // Maps between the two Edwards models
  // ---------------------------------------------------------------------

  // Phi(x, y) = (-x, 1/y).
  //
  // Every affine point of E_{a,d} has y != 0 because a is a non-residue:
  // y = 0 would require x² = 1/a, which has no solution over F_p.
  static EdwardsPoint fromTwistedEdwards(EdwardsPoint P) {
    if (P.y == BigInt.zero) {
      throw ArgumentError('Edwards point with y = 0 is not on E_{a,d}');
    }
    return EdwardsPoint(
      FieldElement.sub(BigInt.zero, P.x),
      FieldElement.inv(P.y),
    );
  }

  // Phi itself is an involution, so the inverse map has the same formula.
  //
  // A dual point with v = 0 is an order-4 point of E_{d,a}. Its preimage is an
  // order-4 point of E_{a,d}, which has no affine coordinates and therefore
  // cannot be represented by EdwardsPoint.
  static EdwardsPoint toTwistedEdwards(EdwardsPoint P) {
    if (P.y == BigInt.zero) {
      throw StateError(
        'the sum is an order-4 point at infinity in the affine E_{a,d} chart',
      );
    }
    return EdwardsPoint(
      FieldElement.sub(BigInt.zero, P.x),
      FieldElement.inv(P.y),
    );
  }

  // ---------------------------------------------------------------------
  // Maps to and from the Montgomery curve
  // ---------------------------------------------------------------------

  // Montgomery (x, y) -> dual Edwards (u, v) = (-x/y, (x+1)/(x-1)).
  //
  // This is the composition Phi o (Montgomery -> E_{a,d}), extended so that
  // the order-2 point maps to (0, -1) and the order-4 points map to v = 0.
  static EdwardsPoint fromMontgomery(MontgomeryPoint P) {
    if (P.isInfinity) return EdwardsPoint.infinity();

    if (P.y == BigInt.zero) {
      // Only (0, 0) has y = 0 on this curve; it is the order-2 point.
      if (P.x == BigInt.zero) {
        return EdwardsPoint(
          BigInt.zero,
          FieldElement.sub(BigInt.zero, BigInt.one),
        );
      }
      throw ArgumentError('invalid Montgomery point with y = 0');
    }

    // The dual chart needs x - 1 invertible. No F_p point has x = 1 because
    // rhs(1) = A + 2 = a is a non-square.
    if (P.x == BigInt.one) {
      throw StateError('Montgomery point with x = 1 is exceptional');
    }

    final u = FieldElement.sub(
      BigInt.zero,
      FieldElement.mul(P.x, FieldElement.inv(P.y)),
    );
    final v = FieldElement.mul(
      FieldElement.add(P.x, BigInt.one),
      FieldElement.inv(FieldElement.sub(P.x, BigInt.one)),
    );
    return EdwardsPoint(u, v);
  }

  // Dual Edwards (u, v) -> Montgomery (x, y) = ((1+v)/(v-1), -x/u).
  static MontgomeryPoint toMontgomery(EdwardsPoint P) {
    if (P.isIdentity) return MontgomeryPoint.infinity();

    if (P.x == BigInt.zero) {
      // On E_{d,a}, x = 0 gives y = ±1. y = 1 is the identity (handled
      // above); y = -1 is the order-2 point.
      if (P.y == FieldElement.sub(BigInt.zero, BigInt.one)) {
        return MontgomeryPoint(BigInt.zero, BigInt.zero);
      }
      throw ArgumentError('invalid dual Edwards point with x = 0');
    }

    final vMinusOne = FieldElement.sub(P.y, BigInt.one);
    if (vMinusOne == BigInt.zero) {
      throw StateError('dual Edwards point with y = 1 is exceptional');
    }

    final x = FieldElement.mul(
      FieldElement.add(BigInt.one, P.y),
      FieldElement.inv(vMinusOne),
    );
    final y = FieldElement.mul(
      FieldElement.sub(BigInt.zero, x),
      FieldElement.inv(P.x),
    );
    return MontgomeryPoint(x, y);
  }

  // Point validation: d x² + y² = 1 + a x²y².
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
  // Point compression: 32 bytes V || 1 byte U-parity
  // ---------------------------------------------------------------------

  // The dual model is the signature curve for Ed256189. Its encoding keeps
  // the sign of u in a separate byte because p is a full 256-bit prime and
  // leaves no spare bit in the 32-byte field element.
  static Uint8List encodePoint(EdwardsPoint P) {
    final vBytes = TwistedEdwards._bigIntToBytes(P.y);
    final signByte = P.x.isOdd ? 1 : 0;
    return Uint8List.fromList([...vBytes, signByte]);
  }

  // Point decompression: recovery of U from compressed V and parity.
  // Returns null for malformed or non-canonical encodings.
  static EdwardsPoint? decodePoint(Uint8List bytes) {
    if (bytes.length != 33) return null;

    // Unlike the natural-model decoder, reject any parity byte other than
    // 0 or 1: the Ed256189 encoding has exactly one valid sign value.
    final signU = bytes[32];
    if (signU > 1) return null;

    final v = TwistedEdwards._bytesToBigInt(bytes.sublist(0, 32));
    if (v >= p) return null;

    // u² = (1 - v²) / (a - d v²)
    final v2 = FieldElement.mul(v, v);
    final denominator = FieldElement.sub(a, FieldElement.mul(d, v2));
    if (denominator == BigInt.zero) return null;

    final numerator = FieldElement.sub(BigInt.one, v2);
    final u2 = FieldElement.mul(numerator, FieldElement.inv(denominator));

    // p = 3 (mod 4), so a square root is u²^((p+1)/4).
    final exp = (p + BigInt.one) >> 2;
    var u = FieldElement.pow(u2, exp);
    if (FieldElement.mul(u, u) != u2) return null;

    if (u == BigInt.zero) {
      // The point (0, v) is its own negative; there is no odd representative.
      if (signU == 1) return null;
    } else if (u.isOdd != (signU == 1)) {
      u = FieldElement.sub(BigInt.zero, u);
    }

    final point = EdwardsPoint(u, v);
    if (!isOnCurve(point)) return null;
    return point;
  }

  // ---------------------------------------------------------------------
  // Complete group law
  // ---------------------------------------------------------------------

  // Standard twisted Edwards addition law on E_{d,a}.
  //
  // Because a' = d is a square and d' = a is a non-square, the two
  // denominators below never vanish for points on the curve. This includes
  // doubling and every mixed-order pair, so unlike the E_{a,d} formula this
  // one needs no exceptional-case branching.
  static EdwardsPoint add(EdwardsPoint P, EdwardsPoint Q) {
    if (P.isIdentity) return Q;
    if (Q.isIdentity) return P;

    final x1 = P.x;
    final y1 = P.y;
    final x2 = Q.x;
    final y2 = Q.y;

    final x1x2 = FieldElement.mul(x1, x2);
    final y1y2 = FieldElement.mul(y1, y2);
    final t = FieldElement.mul(d, FieldElement.mul(x1x2, y1y2));

    final denX = FieldElement.add(BigInt.one, t);
    final denY = FieldElement.sub(BigInt.one, t);

    // Defensive check for off-curve inputs. For valid points these are
    // guaranteed non-zero by the completeness condition.
    if (denX == BigInt.zero || denY == BigInt.zero) {
      throw StateError('DualEdwards.add received an off-curve input');
    }

    // x3 = (x1y2 + y1x2) / (1 + d x1x2y1y2)
    final x3 = FieldElement.mul(
      FieldElement.add(
        FieldElement.mul(x1, y2),
        FieldElement.mul(y1, x2),
      ),
      FieldElement.inv(denX),
    );

    // y3 = (y1y2 - a x1x2) / (1 - d x1x2y1y2)
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
  // This handles the order-4 points of E_{d,a} (which have v = 0) as well.
  //
  // Set [blind] for secret scalars: the Montgomery layer then adds a random
  // multiple of the full curve order, which preserves the result while
  // keeping the ladder's execution independent of the scalar value.
  static EdwardsPoint scalarMul(BigInt k, EdwardsPoint P,
      {bool blind = false}) {
    if (k == BigInt.zero || P.isIdentity) return EdwardsPoint.infinity();
    if (k < BigInt.zero) {
      return scalarMul(-k, negate(P), blind: blind);
    }

    final montP = toMontgomery(P);
    if (montP.isInfinity) return EdwardsPoint.infinity();

    final result = Montgomery.scalarMulFull(k, montP, blind: blind);
    if (result.isInfinity) return EdwardsPoint.infinity();
    return fromMontgomery(result);
  }

  // True iff P is a non-identity point of the prime-order subgroup.
  //
  // Points of order 1, 2, 4 and mixed-order points are rejected. This is the
  // point validation used by Ed256189 for public keys and signature points.
  static bool isInPrimeOrderSubgroup(EdwardsPoint P) {
    if (P.isIdentity) return false;
    if (!isOnCurve(P)) return false;

    // toMontgomery is undefined for x = 0 and y = 1; both are low-order
    // points (identity or order 2), so reject them without converting.
    if (P.x == BigInt.zero) return false;
    if (P.y == BigInt.one) return false;

    final mont = toMontgomery(P);
    return Montgomery.isInPrimeOrderSubgroup(mont);
  }
}
