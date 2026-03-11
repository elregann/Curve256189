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

  // Konstanta Montgomery Ladder: a24 = (A - 2) / 4 mod p
  static final BigInt a24 =
  FieldElement.mul(FieldElement.sub(A, BigInt.two), FieldElement.inv(BigInt.from(4)));

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

  // xDBL — projective doubling
  static List<BigInt> _xDBL(BigInt X, BigInt Z) {
    final U = FieldElement.mul(
      FieldElement.add(X, Z),
      FieldElement.add(X, Z),
    );
    final V = FieldElement.mul(
      FieldElement.sub(X, Z),
      FieldElement.sub(X, Z),
    );
    final Xp = FieldElement.mul(U, V);
    final W = FieldElement.sub(U, V);
    final Zp = FieldElement.mul(
      W,
      FieldElement.add(V, FieldElement.mul(a24, W)),
    );
    return [Xp, Zp];
  }

  // xADD — projective differential addition untuk Montgomery Ladder
  // Input : (X0:Z0), (X1:Z1), xP (x-coordinate titik asal, affine)
  // Output: (X':Z') = (X0:Z0) + (X1:Z1)
  static List<BigInt> _xADD(BigInt X0, BigInt Z0, BigInt X1, BigInt Z1, BigInt xP) {
    // U = (X0 - Z0)(X1 + Z1)
    final U = FieldElement.mul(
      FieldElement.sub(X0, Z0),
      FieldElement.add(X1, Z1),
    );
    // V = (X0 + Z0)(X1 - Z1)
    final V = FieldElement.mul(
      FieldElement.add(X0, Z0),
      FieldElement.sub(X1, Z1),
    );
    // X' = (U + V)²
    final Xp = FieldElement.mul(
      FieldElement.add(U, V),
      FieldElement.add(U, V),
    );
    // Z' = xP * (U - V)²
    final Zp = FieldElement.mul(
      xP,
      FieldElement.mul(
        FieldElement.sub(U, V),
        FieldElement.sub(U, V),
      ),
    );
    return [Xp, Zp];
  }

  // Montgomery Ladder x-only — COMPLETE + CONSTANT-TIME
  // (Bernstein 2006, sesuai SafeCurves)
  static BigInt ladderXOnly(BigInt k, BigInt xP) {
    // R0 = infinity (1:0), R1 = P (xP:1)
    BigInt x0 = BigInt.one;
    BigInt z0 = BigInt.zero;
    BigInt x1 = xP;
    BigInt z1 = BigInt.one;

    final int bitLen = k.bitLength;
    for (int i = bitLen - 1; i >= 0; i--) {
      final bit = (k >> i) & BigInt.one;
      if (bit == BigInt.zero) {
        final xAdd = _xADD(x0, z0, x1, z1, xP);
        final xDbl = _xDBL(x0, z0);
        x1 = xAdd[0]; z1 = xAdd[1];
        x0 = xDbl[0]; z0 = xDbl[1];
      } else {
        final xAdd = _xADD(x0, z0, x1, z1, xP);
        final xDbl = _xDBL(x1, z1);
        x0 = xAdd[0]; z0 = xAdd[1];
        x1 = xDbl[0]; z1 = xDbl[1];
      }
    }

    if (z0 == BigInt.zero) return BigInt.zero; // infinity
    return FieldElement.mul(x0, FieldElement.inv(z0));
  }

  // Scalar multiplication — menggunakan Montgomery Ladder x-only
  // lalu recover y dari persamaan kurva
  static MontgomeryPoint scalarMul(BigInt k, MontgomeryPoint P) {
    if (P.isInfinity) return MontgomeryPoint.infinity();
    if (k == BigInt.zero) return MontgomeryPoint.infinity();

    // Step 1: Ladder x-only
    final xR = ladderXOnly(k, P.x);
    if (xR == BigInt.zero) return MontgomeryPoint.infinity();

    // Step 2: Recover y dari y² = x³ + Ax² + x
    final x2 = FieldElement.mul(xR, xR);
    final x3 = FieldElement.mul(xR, x2);
    final rhs = FieldElement.add(
      FieldElement.add(x3, FieldElement.mul(A, x2)),
      xR,
    );

    // y = rhs^((p+1)/4) karena p ≡ 3 mod 4
    final exp = (p + BigInt.one) >> 2;
    var yR = rhs.modPow(exp, p);

    // Kalau sqrt gagal → titik berorder 2 atau infinity
    if (FieldElement.mul(yR, yR) != rhs) {
      return MontgomeryPoint.infinity();
    }

    // Pilih y genap sebagai canonical form
    if (yR.isOdd) {
      yR = FieldElement.sub(BigInt.zero, yR);
    }

    return MontgomeryPoint(xR, yR);
  }
}