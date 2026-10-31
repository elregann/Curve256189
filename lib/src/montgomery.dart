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

  static final BigInt _n = Curve256189Params.n;

  // Full group order #E = 4n. Adding a multiple of this to a scalar leaves
  // [k]P unchanged for every point on the curve, not just prime-order points.
  static final BigInt _curveOrder = _n * BigInt.from(4);

  // x-coordinates of the low-order points (cofactor h = 4):
  //   order 2: x = 0  (point (0, 0))
  //   order 4: x = p - 1
  static final BigInt _lowOrderX2 = BigInt.zero;
  static final BigInt _lowOrderX4 = p - BigInt.one;

  // y² = x³ + Ax² + x
  static BigInt curveRhs(BigInt x) {
    final x2 = FieldElement.mul(x, x);
    final x3 = FieldElement.mul(x, x2);
    return FieldElement.add(
      FieldElement.add(x3, FieldElement.mul(A, x2)),
      x,
    );
  }

  // Point validation: y² = x³ + Ax² + x
  static bool isOnCurve(MontgomeryPoint point) {
    if (point.isInfinity) return true;
    return FieldElement.mul(point.y, point.y) == curveRhs(point.x);
  }

  // Full point validation for external inputs
  // Rejects infinity, out-of-range, off-curve, and low-order points
  static bool isValidPoint(MontgomeryPoint P) {
    if (P.isInfinity) return false;
    if (P.x <= BigInt.zero || P.x >= p) return false;
    if (P.y < BigInt.zero || P.y >= p) return false;
    if (!isOnCurve(P)) return false;
    if (P.x == _lowOrderX2) return false;
    if (P.x == _lowOrderX4) return false;
    return true;
  }

  // Negation: -(x, y) = (x, -y). Infinity maps to infinity.
  static MontgomeryPoint negate(MontgomeryPoint P) {
    if (P.isInfinity) return MontgomeryPoint.infinity();
    return MontgomeryPoint(P.x, FieldElement.sub(BigInt.zero, P.y));
  }

  // Recover a y-coordinate from x using y = rhs^((p + 1) / 4).
  // Returns null when x is out of range or rhs is not a square.
  // Note: x = 0 is valid and yields y = 0 (the order-2 point).
  static BigInt? yFromX(BigInt x) {
    if (x < BigInt.zero || x >= p) return null;

    final rhs = curveRhs(x);
    if (rhs == BigInt.zero) return BigInt.zero;

    final exp = (p + BigInt.one) >> 2;
    final y = FieldElement.pow(rhs, exp);
    if (FieldElement.mul(y, y) != rhs) return null;
    return y;
  }

  // Decode an x-coordinate into a full point.
  // By default the canonical even-y representative is returned.
  static MontgomeryPoint? pointFromX(BigInt x, {bool evenY = true}) {
    if (x <= BigInt.zero || x >= p) return null;

    var y = yFromX(x);
    if (y == null) return null;

    if (y != BigInt.zero && y.isEven != evenY) {
      y = FieldElement.sub(BigInt.zero, y);
    }

    return MontgomeryPoint(x, y);
  }

  static bool pointsEqual(MontgomeryPoint a, MontgomeryPoint b) {
    if (a.isInfinity || b.isInfinity) {
      return a.isInfinity && b.isInfinity;
    }
    return a.x == b.x && a.y == b.y;
  }

  // Scalar blinding: k' = k + r*(4n), where 4n is the full curve order.
  // This preserves [k]P for every point on the curve.
  static BigInt blindScalar(BigInt k, BigInt r) {
    return k + r * _curveOrder;
  }

  // Blinding entropy and fixed ladder bounds.
  //
  // A blinded scalar is k + r*(4n) with a 64-bit r, so it fits in
  // _blindedLadderBits. The ladder always runs that many iterations for
  // blinded scalars, which keeps its execution length independent of the
  // secret scalar. Unblinded calls use the fixed curve-order length.
  static const int _blindingBits = 64;
  static final int _ladderBits = _curveOrder.bitLength;
  static final int _blindedLadderBits =
      _curveOrder.bitLength + _blindingBits + 1;

  // Uniform non-zero 64-bit blinding scalar.
  static BigInt _randomBlind() {
    final rng = Random.secure();
    BigInt r = BigInt.zero;
    for (int i = 0; i < _blindingBits ~/ 32; i++) {
      r = (r << 32) | BigInt.from(rng.nextInt(0x100000000));
    }
    return r == BigInt.zero ? BigInt.one : r;
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

    // The only point with y = 0 is (0, 0), of order 2: 2P = infinity.
    if (p.y == BigInt.zero) return MontgomeryPoint.infinity();

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

  // Montgomery ladder core.
  //
  // The caller supplies a fixed iteration count. The update step uses an
  // arithmetic conditional swap instead of branching on the secret bit, and
  // both cases always perform the same two field operations.
  // Returns projective [X(kP), Z(kP), X((k+1)P), Z((k+1)P)].
  static List<BigInt> _ladder(BigInt k, BigInt xP, int bitLength) {
    BigInt x0 = BigInt.one;
    BigInt z0 = BigInt.zero;
    BigInt x1 = xP;
    BigInt z1 = BigInt.one;

    // Fall back to a longer loop only for out-of-contract scalars. Blinded
    // scalars are constructed to fit within bitLength.
    final int bits = k.bitLength > bitLength ? k.bitLength : bitLength;
    for (int i = bits - 1; i >= 0; i--) {
      // mask is 0 or -1, so the swap is data-independent at the branch level.
      final mask = -((k >> i) & BigInt.one);

      var dx = (x0 ^ x1) & mask;
      var dz = (z0 ^ z1) & mask;
      x0 ^= dx;
      x1 ^= dx;
      z0 ^= dz;
      z1 ^= dz;

      final xAdd = _xADD(x0, z0, x1, z1, xP);
      final xDbl = _xDBL(x0, z0);

      x1 = xAdd[0];
      z1 = xAdd[1];
      x0 = xDbl[0];
      z0 = xDbl[1];

      dx = (x0 ^ x1) & mask;
      dz = (z0 ^ z1) & mask;
      x0 ^= dx;
      x1 ^= dx;
      z0 ^= dz;
      z1 ^= dz;
    }

    return [x0, z0, x1, z1];
  }

  // Montgomery Ladder (X-only scalar multiplication).
  // Returns null when the result is the point at infinity, and x = 0 when
  // the result is the order-2 point (0, 0).
  //
  // Blinding adds a random multiple of the full curve order, so the result is
  // unchanged for every point on the curve.
  static BigInt? ladderXOnly(BigInt k, BigInt xP, {bool blind = true}) {
    if (k < BigInt.zero) {
      throw ArgumentError('ladderXOnly requires a non-negative scalar');
    }
    if (xP < BigInt.zero || xP >= p) return null;

    final kBlind = blind ? blindScalar(k, _randomBlind()) : k;
    final result = _ladder(
      kBlind,
      xP,
      blind ? _blindedLadderBits : _ladderBits,
    );
    final x = result[0];
    final z = result[1];

    if (z == BigInt.zero) return null;
    return FieldElement.mul(x, FieldElement.inv(z));
  }

  // Montgomery Ladder — returns [x_kP, x_(k+1)P] for Okeya-Sakurai
  // y-recovery. Either element is null when the corresponding x-coordinate
  // is undefined (point at infinity).
  //
  // Blinding uses a multiple of the full curve order and is valid for every
  // point on the curve.
  static List<BigInt?> ladderXWithNext(
    BigInt k,
    BigInt xP, {
    bool blind = false,
  }) {
    if (k < BigInt.zero) {
      throw ArgumentError('ladderXWithNext requires a non-negative scalar');
    }
    if (xP < BigInt.zero || xP >= p) return [null, null];

    final kBlind = blind ? blindScalar(k, _randomBlind()) : k;
    return _ladderXWithNextBits(
      kBlind,
      xP,
      blind ? _blindedLadderBits : _ladderBits,
    );
  }

  // Shared ladder body with an explicit fixed iteration count.
  static List<BigInt?> _ladderXWithNextBits(
    BigInt k,
    BigInt xP,
    int bitLength,
  ) {
    if (xP < BigInt.zero || xP >= p) return [null, null];

    final result = _ladder(k, xP, bitLength);
    final x0 = result[0];
    final z0 = result[1];
    final x1 = result[2];
    final z1 = result[3];

    final xR =
        z0 != BigInt.zero ? FieldElement.mul(x0, FieldElement.inv(z0)) : null;
    final xNext =
        z1 != BigInt.zero ? FieldElement.mul(x1, FieldElement.inv(z1)) : null;
    return [xR, xNext];
  }

  // Double-and-add fallback using full affine arithmetic.
  static MontgomeryPoint _doubleAndAdd(BigInt k, MontgomeryPoint p) {
    MontgomeryPoint result = MontgomeryPoint.infinity();
    MontgomeryPoint addend = p;
    BigInt scalar = k;

    while (scalar > BigInt.zero) {
      if (scalar.isOdd) {
        result = add(result, addend);
      }
      addend = double_(addend);
      scalar = scalar >> 1;
    }
    return result;
  }

  // Full-point scalar multiplication with y-recovery (Okeya-Sakurai 2001).
  //
  // The Montgomery ladder only yields the x-coordinate. The companion point
  // x_(k+1)P lets us recover the correct y (not merely a canonical one):
  //
  //   y_R = ((xP*xR + 1)*(xP + xR + 2A) - 2A - (xP - xR)²*xNext) / (2*yP)
  //
  // A double-and-add fallback is used for exceptional inputs.
  static MontgomeryPoint scalarMulFull(
    BigInt k,
    MontgomeryPoint p, {
    bool blind = false,
  }) {
    if (p.isInfinity) return MontgomeryPoint.infinity();
    if (!isOnCurve(p)) {
      throw ArgumentError('scalarMulFull requires a point on the curve');
    }
    if (k == BigInt.zero) return MontgomeryPoint.infinity();
    if (k < BigInt.zero) {
      return negate(scalarMulFull(-k, p, blind: blind));
    }

    // (0, 0) is the order-2 point and cannot be handled by the ladder.
    if (p.y == BigInt.zero) {
      return k.isOdd ? p : MontgomeryPoint.infinity();
    }

    if (blind) {
      k += _randomBlind() * _curveOrder;
    }

    final pair = _ladderXWithNextBits(
      k,
      p.x,
      blind ? _blindedLadderBits : _ladderBits,
    );
    final xR = pair[0];
    final xNext = pair[1];

    if (xR == null) return MontgomeryPoint.infinity();

    // [k+1]P = O implies [k]P = -P. Handling this directly keeps the
    // secret-dependent double-and-add fallback off the normal path.
    if (xNext == null) return negate(p);

    final rhs = curveRhs(xR);

    final term1 = FieldElement.add(FieldElement.mul(p.x, xR), BigInt.one);
    final term2 = FieldElement.add(
      FieldElement.add(p.x, xR),
      FieldElement.mul(BigInt.two, A),
    );
    final prod = FieldElement.mul(term1, term2);
    final term3 = FieldElement.mul(BigInt.two, A);
    final diff = FieldElement.sub(p.x, xR);
    final diff2 = FieldElement.mul(diff, diff);
    final term4 = FieldElement.mul(diff2, xNext);
    final numer = FieldElement.sub(FieldElement.sub(prod, term3), term4);
    final denom = FieldElement.mul(BigInt.two, p.y);
    final yR = FieldElement.mul(numer, FieldElement.inv(denom));

    if (FieldElement.mul(yR, yR) == rhs) {
      return MontgomeryPoint(xR, yR);
    }

    return _doubleAndAdd(k, p);
  }

  // Backwards-compatible alias for full-point scalar multiplication.
  static MontgomeryPoint scalarMul(BigInt k, MontgomeryPoint p) {
    return scalarMulFull(k, p);
  }

  // True iff P is a non-identity point of the prime-order subgroup.
  static bool isInPrimeOrderSubgroup(MontgomeryPoint P) {
    if (P.isInfinity) return false;
    if (P.x <= BigInt.zero || P.x >= p) return false;
    if (P.y < BigInt.zero || P.y >= p) return false;
    if (!isOnCurve(P)) return false;

    // No blinding here: P is not assumed to be in the prime-order subgroup.
    final nP = scalarMulFull(_n, P, blind: false);
    return nP.isInfinity;
  }

  // Validate a 32-byte x-only public key value.
  // Rejects identity, low-order points, and mixed-order points.
  static bool isValidPublicKeyX(BigInt x) {
    final P = pointFromX(x, evenY: true);
    if (P == null) return false;
    return isInPrimeOrderSubgroup(P);
  }

  // Sum of scalar multiplications: sum(scalars[i] * points[i]).
  static MontgomeryPoint multiScalarMul(
    List<BigInt> scalars,
    List<MontgomeryPoint> points,
  ) {
    if (scalars.length != points.length) {
      throw ArgumentError('scalars and points must have the same length');
    }

    MontgomeryPoint acc = MontgomeryPoint.infinity();
    for (int i = 0; i < scalars.length; i++) {
      if (scalars[i] == BigInt.zero || points[i].isInfinity) continue;
      acc = add(acc, scalarMulFull(scalars[i], points[i]));
    }
    return acc;
  }

  // Uniform non-zero scalar in [1, n).
  static BigInt randomScalar() {
    final rng = Random.secure();
    BigInt r = BigInt.zero;
    for (int i = 0; i < 8; i++) {
      r = (r << 32) | BigInt.from(rng.nextInt(0x100000000));
    }
    r %= _n;
    return r == BigInt.zero ? BigInt.one : r;
  }
}
