import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

bool _same(EdwardsPoint a, EdwardsPoint b) => a.x == b.x && a.y == b.y;

Uint8List _compressed(BigInt y, int signByte) =>
    Uint8List.fromList([...encodeLE32(y), signByte]);

void main() {
  final p = Curve256189Params.p;
  final n = Curve256189Params.n;
  final gMont = MontgomeryPoint.G;
  final gEd = TwistedEdwards.fromMontgomery(gMont);
  final neutral = EdwardsPoint.infinity();

  group('parameters and maps', () {
    test('a = A + 2, d = A - 2', () {
      expect(TwistedEdwards.a, Curve256189Params.A + BigInt.two);
      expect(TwistedEdwards.d, Curve256189Params.A - BigInt.two);
    });

    test('G maps onto the Edwards curve and back', () {
      expect(TwistedEdwards.isOnCurve(gEd), isTrue);
      final back = TwistedEdwards.toMontgomery(gEd);
      expect(back.x, gMont.x);
      expect(back.y, gMont.y);
    });

    test('infinity <-> neutral element', () {
      expect(
          TwistedEdwards.fromMontgomery(MontgomeryPoint.infinity()).isIdentity,
          isTrue);
      expect(TwistedEdwards.toMontgomery(neutral).isInfinity, isTrue);
      expect(TwistedEdwards.isOnCurve(neutral), isTrue);
    });

    test('order-2 point maps to (0, -1) and back', () {
      final ed = TwistedEdwards.fromMontgomery(
          MontgomeryPoint(BigInt.zero, BigInt.zero));
      expect(ed.x, BigInt.zero);
      expect(ed.y, p - BigInt.one);
      expect(TwistedEdwards.isOnCurve(ed), isTrue);
      final mont = TwistedEdwards.toMontgomery(ed);
      expect(mont.x, BigInt.zero);
      expect(mont.y, BigInt.zero);
    });

    test('order-4 Montgomery point is rejected by the Edwards chart', () {
      final x4 = p - BigInt.one;
      final order4 = MontgomeryPoint(x4, Montgomery.yFromX(x4)!);
      expect(() => TwistedEdwards.fromMontgomery(order4), throwsStateError);
    });

    test('a point with y = 0 other than (0, 0) is rejected', () {
      expect(
        () => TwistedEdwards.fromMontgomery(
            MontgomeryPoint(BigInt.one, BigInt.zero)),
        throwsArgumentError,
      );
    });
  });

  group('group law', () {
    test('known answers for 2G and 3G (computed independently in Python)', () {
      final g2 = TwistedEdwards.add(gEd, gEd);
      expect(g2.x,
          big('48193487737828774689595840720804901209767354174254960152610859550694896955344'));
      expect(g2.y,
          big('18084377074664411519307281192043837419640265458317718245545654128148883584435'));
      final g3 = TwistedEdwards.add(g2, gEd);
      expect(g3.x,
          big('97872019178304299916789976022225806947462257696421013298267772176938297900336'));
      expect(g3.y,
          big('61515282157655872155786392657175680064199191908799176873811854210006572012080'));
    });

    test('add agrees with scalarMul and with Montgomery arithmetic', () {
      final g2 = TwistedEdwards.add(gEd, gEd);
      expect(_same(g2, TwistedEdwards.scalarMul(BigInt.two, gEd)), isTrue);
      expect(TwistedEdwards.isOnCurve(g2), isTrue);
      expect(
        _same(g2, TwistedEdwards.fromMontgomery(Montgomery.double_(gMont))),
        isTrue,
      );
      final g3 = TwistedEdwards.add(g2, gEd);
      expect(_same(g3, TwistedEdwards.scalarMul(BigInt.from(3), gEd)), isTrue);
      final g4 = TwistedEdwards.add(g2, g2);
      expect(_same(g4, TwistedEdwards.scalarMul(BigInt.from(4), gEd)), isTrue);
      expect(
        TwistedEdwards.toMontgomery(g4).x,
        Montgomery.add(Montgomery.double_(gMont), Montgomery.double_(gMont)).x,
      );
    });

    test('identity, inverse and commutativity', () {
      expect(_same(TwistedEdwards.add(gEd, neutral), gEd), isTrue);
      expect(_same(TwistedEdwards.add(neutral, gEd), gEd), isTrue);
      expect(TwistedEdwards.add(gEd, TwistedEdwards.negate(gEd)).isIdentity,
          isTrue);
      final g2 = TwistedEdwards.add(gEd, gEd);
      expect(_same(TwistedEdwards.add(gEd, g2), TwistedEdwards.add(g2, gEd)),
          isTrue);
      expect(TwistedEdwards.negate(neutral).isIdentity, isTrue);
    });

    test('scalar 0, negative scalars and the group order', () {
      expect(TwistedEdwards.scalarMul(BigInt.zero, gEd).isIdentity, isTrue);
      expect(TwistedEdwards.scalarMul(BigInt.one, gEd).x, gEd.x);
      expect(
        _same(TwistedEdwards.scalarMul(-BigInt.one, gEd),
            TwistedEdwards.negate(gEd)),
        isTrue,
      );
      expect(TwistedEdwards.scalarMul(n, gEd).isIdentity, isTrue);
      expect(
          TwistedEdwards.scalarMul(BigInt.from(5), neutral).isIdentity, isTrue);
    });

    test('(a + b) G == aG + bG', () {
      final a = big('314159265358979323846264338327950288419716939937510');
      final b = big('271828182845904523536028747135266249775724709369995');
      final sum = TwistedEdwards.add(
          TwistedEdwards.scalarMul(a, gEd), TwistedEdwards.scalarMul(b, gEd));
      expect(_same(sum, TwistedEdwards.scalarMul((a + b) % n, gEd)), isTrue);
    });
  });

  group('compression', () {
    test('33-byte encoding with y little-endian and a parity byte', () {
      final enc = TwistedEdwards.encodePoint(gEd);
      expect(enc.length, 33);
      expect(enc.sublist(0, 32), encodeLE32(gEd.y));
      expect(enc[32], gEd.x.isOdd ? 1 : 0);
    });

    test('round trip for k * G, k = 1..20', () {
      for (var k = 1; k <= 20; k++) {
        final point = TwistedEdwards.scalarMul(BigInt.from(k), gEd);
        final decoded =
            TwistedEdwards.decodePoint(TwistedEdwards.encodePoint(point));
        expect(decoded, isNotNull, reason: 'k=$k');
        expect(_same(decoded!, point), isTrue, reason: 'k=$k');
        expect(TwistedEdwards.isOnCurve(decoded), isTrue);
      }
    });

    test('neutral element round-trips', () {
      final decoded =
          TwistedEdwards.decodePoint(TwistedEdwards.encodePoint(neutral));
      expect(decoded, isNotNull);
      expect(decoded!.isIdentity, isTrue);
    });

    test('wrong lengths are rejected', () {
      expect(TwistedEdwards.decodePoint(Uint8List(0)), isNull);
      expect(TwistedEdwards.decodePoint(Uint8List(32)), isNull);
      expect(TwistedEdwards.decodePoint(Uint8List(34)), isNull);
    });

    test('y >= p is rejected', () {
      expect(TwistedEdwards.decodePoint(_compressed(p, 0)), isNull);
      expect(
          TwistedEdwards.decodePoint(_compressed(p + BigInt.one, 0)), isNull);
    });

    test('y without a square x^2 is rejected', () {
      // y = 2 has no matching x on this curve (checked in Python).
      expect(TwistedEdwards.decodePoint(_compressed(BigInt.two, 0)), isNull);
      expect(TwistedEdwards.decodePoint(_compressed(BigInt.zero, 0)), isNull);
    });

    test('only the least significant bit of the parity byte matters', () {
      final y = BigInt.from(3); // decodable (checked in Python)
      final even = TwistedEdwards.decodePoint(_compressed(y, 0))!;
      final odd = TwistedEdwards.decodePoint(_compressed(y, 1))!;
      expect(even.x.isEven, isTrue);
      expect(odd.x.isOdd, isTrue);
      expect(even.x + odd.x, p);
      for (final b in [2, 4, 0x80, 0xfe]) {
        expect(
            _same(TwistedEdwards.decodePoint(_compressed(y, b))!, even), isTrue,
            reason: 'byte=$b');
      }
      for (final b in [3, 5, 0x81, 0xff]) {
        expect(
            _same(TwistedEdwards.decodePoint(_compressed(y, b))!, odd), isTrue,
            reason: 'byte=$b');
      }
    });
  });

  group('dual curve E_{d,a} (complete addition)', () {
    final order2Mont = MontgomeryPoint(BigInt.zero, BigInt.zero);
    final order4Mont = MontgomeryPoint(
      p - BigInt.one,
      Montgomery.yFromX(p - BigInt.one)!,
    );
    final order4Dual = DualEdwards.fromMontgomery(order4Mont);
    final phiG = DualEdwards.fromTwistedEdwards(gEd);

    test("coefficients are swapped: a' = d, d' = a", () {
      expect(DualEdwards.a, Curve256189Params.d);
      expect(DualEdwards.d, Curve256189Params.aEd);
      expect(DualEdwards.a, BigInt.from(61368));
      expect(DualEdwards.d, BigInt.from(61372));
    });

    test('Phi(G) matches the independently computed known answer', () {
      expect(
        phiG.x,
        big('73497007203071883455386616803268707909822129227127001819386623447574380726635'),
      );
      expect(
        phiG.y,
        big('92633671389852956338856788006950326282615987732512451231566067206330503711799'),
      );
    });

    test('Phi is an involution and preserves the curve', () {
      expect(DualEdwards.isOnCurve(phiG), isTrue);
      expect(_same(DualEdwards.toTwistedEdwards(phiG), gEd), isTrue);
      for (var k = 1; k <= 10; k++) {
        final point = TwistedEdwards.scalarMul(BigInt.from(k), gEd);
        final dual = DualEdwards.fromTwistedEdwards(point);
        expect(DualEdwards.isOnCurve(dual), isTrue, reason: 'k=$k');
        expect(_same(DualEdwards.toTwistedEdwards(dual), point), isTrue,
            reason: 'k=$k');
      }
    });

    test('Montgomery maps round-trip, including order-2 and order-4 points',
        () {
      final points = <MontgomeryPoint>[
        MontgomeryPoint.G,
        Montgomery.double_(MontgomeryPoint.G),
        Montgomery.add(MontgomeryPoint.G, order2Mont),
        order2Mont,
        order4Mont,
        Montgomery.negate(order4Mont),
      ];
      for (final point in points) {
        final dual = DualEdwards.fromMontgomery(point);
        expect(DualEdwards.isOnCurve(dual), isTrue);
        final back = DualEdwards.toMontgomery(dual);
        expect(back.x, point.x);
        expect(back.y, point.y);
      }
      expect(
        DualEdwards.fromMontgomery(MontgomeryPoint.infinity()).isIdentity,
        isTrue,
      );
      expect(
        DualEdwards.toMontgomery(EdwardsPoint.infinity()).isInfinity,
        isTrue,
      );
    });

    test('order-4 point has v = 0 and doubles to the order-2 point', () {
      expect(order4Dual.y, BigInt.zero);
      expect(DualEdwards.isOnCurve(order4Dual), isTrue);
      final twice = DualEdwards.add(order4Dual, order4Dual);
      expect(twice.x, BigInt.zero);
      expect(twice.y, p - BigInt.one);
    });

    test('addition is complete for every mixed-order pair in a grid', () {
      final montPoints = <MontgomeryPoint>[];
      for (var k = 0; k <= 10; k++) {
        final kG = Montgomery.scalarMulFull(BigInt.from(k), MontgomeryPoint.G);
        montPoints.add(kG);
        montPoints.add(Montgomery.add(kG, order2Mont));
      }
      final edPoints = montPoints.map(TwistedEdwards.fromMontgomery).toList();
      final dualPoints = montPoints.map(DualEdwards.fromMontgomery).toList();

      for (var i = 0; i < montPoints.length; i++) {
        for (var j = 0; j < montPoints.length; j++) {
          final expected = TwistedEdwards.fromMontgomery(
              Montgomery.add(montPoints[i], montPoints[j]));

          final dualSum = DualEdwards.add(dualPoints[i], dualPoints[j]);
          expect(
            _same(DualEdwards.toTwistedEdwards(dualSum), expected),
            isTrue,
            reason: 'dual i=$i j=$j',
          );

          final sum = TwistedEdwards.add(edPoints[i], edPoints[j]);
          expect(_same(sum, expected), isTrue, reason: 'twisted i=$i j=$j');
        }
      }
    });

    test('TwistedEdwards.add handles a difference of order 4', () {
      // The old law fails when Q - P is one of the two order-4 points.
      // Their sum is still affine, so the dual-curve route must succeed.
      for (final k in [1, 2, 3, 5, 7]) {
        final point =
            Montgomery.scalarMulFull(BigInt.from(k), MontgomeryPoint.G);
        final other = Montgomery.add(point, order4Mont);
        expect(
          Montgomery.add(other, Montgomery.negate(point)).x,
          p - BigInt.one,
        );
        final expected =
            TwistedEdwards.fromMontgomery(Montgomery.add(point, other));
        final got = TwistedEdwards.add(
          TwistedEdwards.fromMontgomery(point),
          TwistedEdwards.fromMontgomery(other),
        );
        expect(_same(got, expected), isTrue, reason: 'k=$k');
      }
    });

    test('a sum that is an order-4 point is reported, not miscomputed', () {
      // Q = T - G, so G + Q = T is one of the two points at infinity in the
      // affine E_{a,d} chart. There is no affine EdwardsPoint for it.
      final other =
          Montgomery.add(order4Mont, Montgomery.negate(MontgomeryPoint.G));
      final edOther = TwistedEdwards.fromMontgomery(other);
      expect(() => TwistedEdwards.add(gEd, edOther), throwsStateError);

      // The dual layer itself still evaluates the sum without exception;
      // the result is the dual order-4 point with v = 0.
      final dualSum = DualEdwards.add(
        DualEdwards.fromTwistedEdwards(gEd),
        DualEdwards.fromTwistedEdwards(edOther),
      );
      expect(dualSum.y, BigInt.zero);
      expect(DualEdwards.isOnCurve(dualSum), isTrue);
    });

    test('dual scalar multiplication, including order 4', () {
      expect(_same(DualEdwards.scalarMul(n, phiG), EdwardsPoint.infinity()),
          isTrue);
      final twice = DualEdwards.scalarMul(BigInt.two, order4Dual);
      expect(twice.x, BigInt.zero);
      expect(twice.y, p - BigInt.one);

      for (var k = 1; k <= 8; k++) {
        final expected = DualEdwards.fromTwistedEdwards(
            TwistedEdwards.scalarMul(BigInt.from(k), gEd));
        expect(_same(DualEdwards.scalarMul(BigInt.from(k), phiG), expected),
            isTrue,
            reason: 'k=$k');
      }
    });
  });
}
