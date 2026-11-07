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
      expect(TwistedEdwards.fromMontgomery(MontgomeryPoint.infinity()).isIdentity,
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
      expect(g2.x, big('21139268206049116928676975743202453917186415086493671641027732212943946194658'));
      expect(g2.y, big('13231049920630494911006005234037179308900026138458843802808173353656369168193'));
      final g3 = TwistedEdwards.add(g2, gEd);
      expect(g3.x, big('55879295218307178301755564472240605795605755367081555482933764954389577256340'));
      expect(g3.y, big('59172688796580269347023790601365730409653073173664840903656268292671020546887'));
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
      expect(TwistedEdwards.scalarMul(BigInt.from(5), neutral).isIdentity,
          isTrue);
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
        final decoded = TwistedEdwards.decodePoint(
            TwistedEdwards.encodePoint(point));
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
      expect(TwistedEdwards.decodePoint(_compressed(p + BigInt.one, 0)), isNull);
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
        expect(_same(TwistedEdwards.decodePoint(_compressed(y, b))!, even),
            isTrue,
            reason: 'byte=$b');
      }
      for (final b in [3, 5, 0x81, 0xff]) {
        expect(_same(TwistedEdwards.decodePoint(_compressed(y, b))!, odd),
            isTrue,
            reason: 'byte=$b');
      }
    });
  });
}
