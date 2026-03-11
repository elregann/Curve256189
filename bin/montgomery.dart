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

  // Konstanta Montgomery Ladder: a24 = (A + 2) / 4 mod p
  static final BigInt a24 =
  FieldElement.mul(FieldElement.add(A, BigInt.two), FieldElement.inv(BigInt.from(4)));

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
    final BigInt A = Curve256189Params.A;

    final BigInt X2 = FieldElement.mul(X, X);
    final BigInt Z2 = FieldElement.mul(Z, Z);
    final BigInt XZ = FieldElement.mul(X, Z);

    final BigInt X3 = FieldElement.mul(
        FieldElement.sub(X2, Z2),
        FieldElement.sub(X2, Z2)
    );

    final BigInt temp = FieldElement.add(
        FieldElement.add(X2, FieldElement.mul(A, XZ)),
        Z2
    );
    final BigInt Z3 = FieldElement.mul(
        FieldElement.mul(BigInt.from(4), XZ),
        temp
    );

    return [X3, Z3];
  }

  static List<BigInt> _xADD(BigInt Xp, BigInt Zp, BigInt Xq, BigInt Zq, BigInt x) {
    final BigInt U = FieldElement.mul(
        FieldElement.sub(Xp, Zp),
        FieldElement.add(Xq, Zq)
    );
    final BigInt V = FieldElement.mul(
        FieldElement.add(Xp, Zp),
        FieldElement.sub(Xq, Zq)
    );
    final BigInt add = FieldElement.add(U, V);
    final BigInt sub = FieldElement.sub(U, V);
    final BigInt Xr = FieldElement.mul(add, add);
    final BigInt Zr = FieldElement.mul(x, FieldElement.mul(sub, sub));
    return [Xr, Zr];
  }

  static BigInt ladderXOnly(BigInt k, BigInt xP) {
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
        x1 = xAdd[0];
        z1 = xAdd[1];
        x0 = xDbl[0];
        z0 = xDbl[1];
      } else {
        final xAdd = _xADD(x0, z0, x1, z1, xP);
        final xDbl = _xDBL(x1, z1);
        x0 = xAdd[0];
        z0 = xAdd[1];
        x1 = xDbl[0];
        z1 = xDbl[1];
      }
    }

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