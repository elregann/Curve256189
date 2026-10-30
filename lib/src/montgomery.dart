// montgomery.dart

import 'dart:math';
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

  // Optimized constant: a24 = (A + 2) / 4 mod p
  static final BigInt a24 = Curve256189Params.a24;

  // Point validation: y² = x³ + Ax² + x
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

  // Low-order point x-coordinates (derived from cofactor h=4)
  // Order 2: x = 0 (point (0,0))
  // Order 4: x = p-1
  static final BigInt _lowOrderX2 = BigInt.zero;
  static final BigInt _lowOrderX4 = p - BigInt.one;

  // Full point validation for external inputs
  // Rejects infinity, out-of-range, off-curve, and low-order points
  static bool isValidPoint(MontgomeryPoint P) {
    // Check 1: not infinity
    if (P.isInfinity) return false;

    // Check 2: coordinates in valid range (0 < x < p)
    if (P.x <= BigInt.zero || P.x >= p) return false;
    if (P.y <= BigInt.zero || P.y >= p) return false;

    // Check 3: point lies on curve y² = x³ + Ax² + x
    if (!isOnCurve(P)) return false;

    // Check 4: reject low-order points (small subgroup attack prevention)
    if (P.x == _lowOrderX2) return false;
    if (P.x == _lowOrderX4) return false;

    return true;
  }

  // Scalar blinding: k' = k + r*n
  // Protects private key from timing attacks via randomized scalar
  // Result: ladderXOnly(k', P) == ladderXOnly(k, P) since r*n*G = infinity
  static BigInt blindScalar(BigInt k, BigInt r) {
    return k + r * Curve256189Params.n;
  }

  // Affine point addition
  static MontgomeryPoint add(MontgomeryPoint p, MontgomeryPoint q) {
    if (p.isInfinity) return q;
    if (q.isInfinity) return p;
    if (p.x == q.x) {
      if (p.y != q.y) return MontgomeryPoint.infinity();
      return double_(p);
    }

    // Slope: lambda = (y2 - y1) / (x2 - x1)
    final dy = FieldElement.sub(q.y, p.y);
    final dx = FieldElement.sub(q.x, p.x);
    final lambda = FieldElement.mul(dy, FieldElement.inv(dx));

    // Result x: x3 = lambda² - A - x1 - x2
    final x3 = FieldElement.sub(
      FieldElement.sub(
        FieldElement.sub(FieldElement.mul(lambda, lambda), A),
        p.x,
      ),
      q.x,
    );

    // Result y: y3 = lambda(x1 - x3) - y1
    final y3 = FieldElement.sub(
      FieldElement.mul(lambda, FieldElement.sub(p.x, x3)),
      p.y,
    );

    return MontgomeryPoint(x3, y3);
  }

  // Affine point doubling
  static MontgomeryPoint double_(MontgomeryPoint p) {
    if (p.isInfinity) return p;

    // Slope: lambda = (3x² + 2Ax + 1) / (2y)
    final x2 = FieldElement.mul(p.x, p.x);
    final numerator = FieldElement.add(
      FieldElement.add(
        FieldElement.mul(BigInt.from(3), x2),
        FieldElement.mul(BigInt.two * A, p.x),
      ),
      BigInt.one,
    );
    final denominator = FieldElement.mul(BigInt.two, p.y);
    final lambda = FieldElement.mul(numerator, FieldElement.inv(denominator));

    // Result x: x3 = lambda² - A - 2x
    final x3 = FieldElement.sub(
      FieldElement.sub(FieldElement.mul(lambda, lambda), A),
      FieldElement.mul(BigInt.two, p.x),
    );

    // Result y: y3 = lambda(x - x3) - y
    final y3 = FieldElement.sub(
      FieldElement.mul(lambda, FieldElement.sub(p.x, x3)),
      p.y,
    );

    return MontgomeryPoint(x3, y3);
  }

  // Projective doubling (X:Z)
  static List<BigInt> _xDBL(BigInt xCoord, BigInt zCoord) {
    final x2 = FieldElement.mul(xCoord, xCoord);
    final z2 = FieldElement.mul(zCoord, zCoord);
    final xz = FieldElement.mul(xCoord, zCoord);

    final xOut = FieldElement.mul(
      FieldElement.sub(x2, z2),
      FieldElement.sub(x2, z2),
    );

    final temp = FieldElement.add(
      FieldElement.add(x2, FieldElement.mul(A, xz)),
      z2,
    );
    final zOut = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), xz),
      temp,
    );

    return [xOut, zOut];
  }

  // Differential addition (X:Z)
  static List<BigInt> _xADD(
      BigInt xp, BigInt zp, BigInt xq, BigInt zq, BigInt x) {
    final u = FieldElement.mul(
      FieldElement.sub(xp, zp),
      FieldElement.add(xq, zq),
    );
    final v = FieldElement.mul(
      FieldElement.add(xp, zp),
      FieldElement.sub(xq, zq),
    );
    final sum = FieldElement.add(u, v);
    final diff = FieldElement.sub(u, v);
    final xr = FieldElement.mul(sum, sum);
    final zr = FieldElement.mul(x, FieldElement.mul(diff, diff));
    return [xr, zr];
  }

  // Montgomery Ladder (X-only scalar multiplication)
  static BigInt ladderXOnly(BigInt k, BigInt xP) {
    // Scalar blinding — new random r per call via cryptographic RNG
    final r = BigInt.from(Random.secure().nextInt(0xFFFFFFFF));
    final kBlind = blindScalar(k, r);

    BigInt x0 = BigInt.one;
    BigInt z0 = BigInt.zero;
    BigInt x1 = xP;
    BigInt z1 = BigInt.one;

    final int bitLen = kBlind.bitLength;
    for (int i = bitLen - 1; i >= 0; i--) {
      final bit = (kBlind >> i) & BigInt.one;
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

  // Montgomery Ladder — returns [x_kP, x_(k+1)P] for Okeya-Sakurai y-recovery
  // Note: no scalar blinding here — blinding breaks x_(k+1)P consistency
  // Security: called only from TwistedEdwards.scalarMul with internal k
  static List<BigInt?> ladderXWithNext(BigInt k, BigInt xP) {
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

    final xR    = z0 != BigInt.zero ? FieldElement.mul(x0, FieldElement.inv(z0)) : null;
    final xNext = z1 != BigInt.zero ? FieldElement.mul(x1, FieldElement.inv(z1)) : null;
    return [xR, xNext];
  }

  // Scalar multiplication with Y-recovery
  static MontgomeryPoint scalarMul(BigInt k, MontgomeryPoint p) {
    if (p.isInfinity) return MontgomeryPoint.infinity();
    if (k == BigInt.zero) return MontgomeryPoint.infinity();

    // Step 1: Ladder x-only
    final xR = ladderXOnly(k, p.x);
    if (xR == BigInt.zero) return MontgomeryPoint.infinity();

    // Step 2: Recover y from y² = x³ + Ax² + x
    final x2 = FieldElement.mul(xR, xR);
    final x3 = FieldElement.mul(xR, x2);
    final rhs = FieldElement.add(
      FieldElement.add(x3, FieldElement.mul(A, x2)),
      xR,
    );

    // Quadratic residue: y = rhs^((p+1)/4)
    final exp = (Montgomery.p + BigInt.one) >> 2;
    var yR = FieldElement.pow(rhs, exp);

    // Verify y coordinate validity
    if (FieldElement.mul(yR, yR) != rhs) {
      return MontgomeryPoint.infinity();
    }

    // Canonical form: Y-parity control
    if (yR.isOdd) {
      yR = FieldElement.sub(BigInt.zero, yR);
    }

    return MontgomeryPoint(xR, yR);
  }
}