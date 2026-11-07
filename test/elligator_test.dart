import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  final p = Curve256189Params.p;
  final aCoef = Curve256189Params.A;
  final u = Elligator.u;
  final half = p >> 1;

  group('encode', () {
    test('published test vectors', () {
      final vectors = {
        1: '38597363079105398474523661669562635951089994888546854679819194669304376226851',
        2: '90060513851245929773888543895646150552543321406609327586244787561710211515717',
        42: '51481379431382575976079023938405023355562653992742999427007353161920005302563',
      };
      vectors.forEach((t, want) {
        expect(Elligator.encode(BigInt.from(t)), big(want), reason: 't=$t');
      });
    });

    test('t = 0 is not encodable', () {
      expect(Elligator.encode(BigInt.zero), isNull);
    });

    test('output always lies on the curve', () {
      for (final t in [1, 2, 3, 100, 999, 12345678, 987654321]) {
        final x = Elligator.encode(BigInt.from(t));
        expect(x, isNotNull, reason: 't=$t');
        expect(Montgomery.yFromX(x!), isNotNull, reason: 't=$t');
      }
      for (final t in [half, half + BigInt.one, p - BigInt.one]) {
        final x = Elligator.encode(t);
        expect(x, isNotNull);
        expect(Montgomery.yFromX(x!), isNotNull);
      }
    });

    test('t and -t give the same x', () {
      for (final t in [1, 7, 4242]) {
        final bt = BigInt.from(t);
        expect(Elligator.encode(bt), Elligator.encode(p - bt));
      }
    });
  });

  group('exceptional case 1 + u t^2 == 0 (RFC 9380 section 6.7.1)', () {
    // sqrt(-1/u), canonical representative (computed independently in Python).
    final t0 = big('31030605534276244588514433954599146277984599876055206801028946312282397445893');
    final minusA = p - aCoef;

    test('t0 is really exceptional', () {
      final denom = FieldElement.add(
          BigInt.one, FieldElement.mul(u, FieldElement.mul(t0, t0)));
      expect(denom, BigInt.zero);
    });

    test('encode returns -A, not the order-2 point', () {
      for (final t in [t0, p - t0]) {
        final x = Elligator.encode(t);
        expect(x, isNotNull);
        expect(x, isNot(BigInt.zero));
        expect(x, minusA);
        expect(Montgomery.yFromX(x!), isNotNull);
      }
    });

    test('decode(-A) returns the canonical t and round-trips', () {
      final decoded = Elligator.decode(minusA);
      expect(decoded, t0);
      expect(Elligator.encode(decoded!), minusA);
    });
  });

  group('decode', () {
    test('returns a canonical t (<= (p - 1) / 2) that encodes back', () {
      for (final t in [1, 2, 3, 42, 100, 999, 12345678, 987654321]) {
        final x = Elligator.encode(BigInt.from(t))!;
        final back = Elligator.decode(x);
        expect(back, isNotNull, reason: 't=$t');
        expect(back! <= half, isTrue, reason: 't=$t');
        expect(Elligator.encode(back), x, reason: 't=$t');
      }
    });

    test('t on the first branch decodes to itself', () {
      for (final t in [12345678, 987654321]) {
        final x = Elligator.encode(BigInt.from(t))!;
        expect(Elligator.decode(x), BigInt.from(t));
      }
    });

    test('roughly half of the curve points are representable', () {
      var decodable = 0, notDecodable = 0;
      for (var k = 2; k < 60; k++) {
        final point = Montgomery.scalarMulFull(BigInt.from(k), MontgomeryPoint.G);
        if (Elligator.decode(point.x) != null) {
          decodable++;
        } else {
          notDecodable++;
        }
      }
      // 25 of the 58 points k * G, k = 2..59, are representable.
      expect(decodable, 25);
      expect(notDecodable, 33);
    });

    test('x = 0 is not decodable', () {
      expect(Elligator.decode(BigInt.zero), isNull);
      expect(Elligator.decode(p), isNull);
    });
  });
}
