import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

MontgomeryPoint _naiveMul(BigInt k, MontgomeryPoint point) {
  var result = MontgomeryPoint.infinity();
  var addend = point;
  var scalar = k;
  while (scalar > BigInt.zero) {
    if (scalar.isOdd) result = Montgomery.add(result, addend);
    addend = Montgomery.double_(addend);
    scalar >>= 1;
  }
  return result;
}

void main() {
  final g = MontgomeryPoint.G;
  final n = Curve256189Params.n;
  final p = Curve256189Params.p;
  final order2 = MontgomeryPoint(BigInt.zero, BigInt.zero);
  final x4 = p - BigInt.one;
  final order4 = MontgomeryPoint(x4, Montgomery.yFromX(x4)!);
  final mixed = Montgomery.add(g, order2);

  group('known answers (computed independently in Python)', () {
    test('2G, 3G, 4G', () {
      final g2 = Montgomery.scalarMulFull(BigInt.two, g);
      expect(g2.x, big('71702383869856642770344903927731741473437292229191794436086656795143485823472'));
      expect(g2.y, big('57363726468860733750451189193045550261171111216048082171380039097975535793301'));

      final g3 = Montgomery.scalarMulFull(BigInt.from(3), g);
      expect(g3.x, big('14115666474119806464227609162703856245675945261003141602085662706771368881379'));
      expect(g3.y, big('83106376866341491647172049181615210947460868157176566557219288467553356029720'));

      final g4 = Montgomery.scalarMulFull(BigInt.from(4), g);
      expect(g4.x, big('74570479769107260763191732626167571959616451960889668458732909790964950787294'));
      expect(g4.y, big('50973944465980728372257055003499441406282214920689735945547903951881896540149'));
    });

    test('x-only ladder agrees on 2G, 3G, 4G', () {
      expect(Montgomery.ladderXOnly(BigInt.two, g.x),
          big('71702383869856642770344903927731741473437292229191794436086656795143485823472'));
      expect(Montgomery.ladderXOnly(BigInt.from(3), g.x, blind: false),
          big('14115666474119806464227609162703856245675945261003141602085662706771368881379'));
      expect(Montgomery.ladderXOnly(BigInt.from(4), g.x, blind: false),
          big('74570479769107260763191732626167571959616451960889668458732909790964950787294'));
    });

    test('order-4 point (p-1, sqrt(A-2)) and mixed-order point G + (0,0)', () {
      expect(order4.y,
          anyOf(
            big('80492744670248143968696479090130607422449092265214152367442002500378944457818'),
            p - big('80492744670248143968696479090130607422449092265214152367442002500378944457818'),
          ));
      expect(mixed.x,
          big('96493407697763496186309154173906589877724987221367136699547986673260941366456'));
      expect(mixed.y,
          big('89101702883703883876928912383689139018523241516461205331989704332383423213211'));
    });
  });

  group('group law', () {
    test('doubling and addition', () {
      final g2 = Montgomery.double_(g);
      expect(Montgomery.isOnCurve(g2), isTrue);
      expect(Montgomery.pointsEqual(Montgomery.add(g, g), g2), isTrue);
      expect(
        Montgomery.pointsEqual(
            Montgomery.scalarMulFull(BigInt.from(4), g), Montgomery.double_(g2)),
        isTrue,
      );
    });

    test('identity and inverse', () {
      final inf = MontgomeryPoint.infinity();
      expect(Montgomery.pointsEqual(Montgomery.add(inf, g), g), isTrue);
      expect(Montgomery.pointsEqual(Montgomery.add(g, inf), g), isTrue);
      expect(Montgomery.pointsEqual(inf, MontgomeryPoint.infinity()), isTrue);
      expect(Montgomery.pointsEqual(inf, g), isFalse);
      expect(Montgomery.add(g, Montgomery.negate(g)).isInfinity, isTrue);
    });

    test('associativity and commutativity', () {
      final a = Montgomery.scalarMulFull(BigInt.from(5), g);
      final b = Montgomery.scalarMulFull(BigInt.from(11), g);
      final c = Montgomery.scalarMulFull(BigInt.from(17), g);
      expect(Montgomery.pointsEqual(Montgomery.add(a, b), Montgomery.add(b, a)),
          isTrue);
      expect(
        Montgomery.pointsEqual(
          Montgomery.add(Montgomery.add(a, b), c),
          Montgomery.add(a, Montgomery.add(b, c)),
        ),
        isTrue,
      );
    });

    test('order-2 point doubles to infinity', () {
      expect(Montgomery.double_(order2).isInfinity, isTrue);
      expect(Montgomery.scalarMulFull(BigInt.two, order2).isInfinity, isTrue);
    });

    test('order-4 point: 2P = (0,0), 4P = infinity', () {
      final twice = Montgomery.double_(order4);
      expect(Montgomery.pointsEqual(twice, order2), isTrue);
      expect(Montgomery.scalarMulFull(BigInt.from(4), order4).isInfinity,
          isTrue);
    });
  });

  group('scalar multiplication', () {
    test('matches double-and-add', () {
      for (final k in [1, 2, 3, 13, 255, 1024, 65537]) {
        expect(
          Montgomery.pointsEqual(
              Montgomery.scalarMulFull(BigInt.from(k), g),
              _naiveMul(BigInt.from(k), g)),
          isTrue,
          reason: 'k=$k',
        );
      }
    });

    test('scalar 0, negative scalars and the group order', () {
      expect(Montgomery.scalarMulFull(BigInt.zero, g).isInfinity, isTrue);
      final negG = Montgomery.scalarMulFull(BigInt.from(-1), g);
      expect(Montgomery.pointsEqual(negG, Montgomery.negate(g)), isTrue);
      expect(Montgomery.scalarMulFull(n, g).isInfinity, isTrue);
      expect(
        Montgomery.pointsEqual(
            Montgomery.scalarMulFull(n - BigInt.one, g), negG),
        isTrue,
      );
      expect(
        Montgomery.pointsEqual(
            Montgomery.scalarMulFull(n + BigInt.one, g), g),
        isTrue,
      );
    });

    test('(a + b) G == aG + bG', () {
      final a = big('314159265358979323846264338327950288419716939937510');
      final b = big('271828182845904523536028747135266249775724709369995');
      final sum = Montgomery.add(
          Montgomery.scalarMulFull(a, g), Montgomery.scalarMulFull(b, g));
      expect(
        Montgomery.pointsEqual(Montgomery.scalarMulFull((a + b) % n, g), sum),
        isTrue,
      );
    });

    test('rejects a point that is not on the curve', () {
      final off = MontgomeryPoint(g.x, (g.y + BigInt.one) % p);
      expect(() => Montgomery.scalarMulFull(BigInt.two, off),
          throwsArgumentError);
    });

    test('multiScalarMul and length check', () {
      final a = BigInt.from(7), b = BigInt.from(9);
      final g2 = Montgomery.double_(g);
      final sum = Montgomery.multiScalarMul([a, b], [g, g2]);
      expect(
        Montgomery.pointsEqual(
            sum, Montgomery.scalarMulFull(BigInt.from(25), g)),
        isTrue,
      );
      expect(() => Montgomery.multiScalarMul([a], [g, g2]),
          throwsArgumentError);
    });

    test('randomScalar is in [1, n)', () {
      for (var i = 0; i < 50; i++) {
        final k = Montgomery.randomScalar();
        expect(k > BigInt.zero && k < n, isTrue);
      }
    });
  });

  group('scalar blinding', () {
    final k = big('12345678901234567890');
    final large = (BigInt.one << 300) + BigInt.from(12345);

    test('blindScalar adds a multiple of 4n', () {
      final r = Montgomery.blindScalar(k, BigInt.from(5));
      expect(r, k + BigInt.from(5) * BigInt.from(4) * n);
      expect(Montgomery.blindScalar(k, BigInt.one) !=
          Montgomery.blindScalar(k, BigInt.two), isTrue);
    });

    test('ladderXOnly result does not depend on the blinding', () {
      final results = {
        for (var i = 0; i < 5; i++) Montgomery.ladderXOnly(k, g.x),
        Montgomery.ladderXOnly(k, g.x, blind: false),
      };
      expect(results.length, 1);
      expect(results.first, isNotNull);
    });

    test('ladderXOnly(n) is infinity (null)', () {
      expect(Montgomery.ladderXOnly(n, g.x, blind: false), isNull);
      expect(Montgomery.ladderXOnly(n, g.x), isNull);
    });

    test('ladderXOnly rejects negative scalars', () {
      expect(() => Montgomery.ladderXOnly(BigInt.from(-1), g.x),
          throwsArgumentError);
    });

    test('blinded and plain scalarMulFull agree on all point classes', () {
      for (final point in [g, order4, mixed]) {
        for (final scalar in [BigInt.from(3), k, large]) {
          expect(
            Montgomery.pointsEqual(
              Montgomery.scalarMulFull(scalar, point),
              Montgomery.scalarMulFull(scalar, point, blind: true),
            ),
            isTrue,
            reason: 'scalar=$scalar',
          );
        }
      }
    });
  });

  group('point validation', () {
    test('G and 2G are valid prime-order points', () {
      final g2 = Montgomery.double_(g);
      for (final pt in [g, g2]) {
        expect(Montgomery.isValidPoint(pt), isTrue);
        expect(Montgomery.isInPrimeOrderSubgroup(pt), isTrue);
        expect(Montgomery.isValidPublicKeyX(pt.x), isTrue);
      }
    });

    test('infinity and low-order points are rejected', () {
      expect(Montgomery.isValidPoint(MontgomeryPoint.infinity()), isFalse);
      expect(Montgomery.isValidPoint(order2), isFalse);
      expect(Montgomery.isValidPoint(order4), isFalse);
      expect(Montgomery.isInPrimeOrderSubgroup(order2), isFalse);
      expect(Montgomery.isInPrimeOrderSubgroup(order4), isFalse);
      expect(Montgomery.isValidPublicKeyX(BigInt.zero), isFalse);
      expect(Montgomery.isValidPublicKeyX(x4), isFalse);
    });

    test('mixed-order point is on the curve but not in the subgroup', () {
      expect(Montgomery.isOnCurve(mixed), isTrue);
      expect(Montgomery.isInPrimeOrderSubgroup(mixed), isFalse);
      expect(Montgomery.isValidPublicKeyX(mixed.x), isFalse);
    });

    test('out-of-range coordinates are rejected', () {
      expect(Montgomery.isValidPoint(MontgomeryPoint(p, BigInt.one)), isFalse);
      expect(Montgomery.isValidPoint(MontgomeryPoint(-BigInt.one, BigInt.one)),
          isFalse);
      expect(Montgomery.isValidPublicKeyX(p), isFalse);
      expect(Montgomery.isValidPublicKeyX(-BigInt.one), isFalse);
    });

    test('twist x-coordinates are rejected', () {
      // x = 1 and x = 4 have a non-square right-hand side (checked in Python).
      for (final x in [1, 4]) {
        final bx = BigInt.from(x);
        final rhs = Montgomery.curveRhs(bx);
        expect(FieldElement.pow(rhs, (p - BigInt.one) >> 1), p - BigInt.one);
        expect(Montgomery.yFromX(bx), isNull);
        expect(Montgomery.pointFromX(bx), isNull);
        expect(Montgomery.isValidPublicKeyX(bx), isFalse);
      }
    });
  });

  group('x-coordinate decoding', () {
    test('pointFromX recovers G with even y by default', () {
      final even = Montgomery.pointFromX(g.x)!;
      expect(even.y.isEven, isTrue);
      expect(Montgomery.isOnCurve(even), isTrue);
      final odd = Montgomery.pointFromX(g.x, evenY: false)!;
      expect(odd.y.isOdd, isTrue);
      expect(even.y + odd.y, p);
      expect(g.y == even.y || g.y == odd.y, isTrue);
    });

    test('bounds', () {
      expect(Montgomery.pointFromX(BigInt.zero), isNull);
      expect(Montgomery.pointFromX(p), isNull);
      expect(Montgomery.pointFromX(-BigInt.one), isNull);
      expect(Montgomery.yFromX(BigInt.zero), BigInt.zero);
    });
  });
}
