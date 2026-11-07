@Tags(['slow'])
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

// Randomised and long-running checks. Skip them for a quick run with:
//   dart test -x slow
// A fixed seed keeps failures reproducible.

BigInt _randomBelow(Random rng, BigInt bound) {
  var v = BigInt.zero;
  for (var i = 0; i < 9; i++) {
    v = (v << 32) | BigInt.from(rng.nextInt(0x100000000));
  }
  return v % bound;
}

Uint8List _randomBytes(Random rng, int length) =>
    Uint8List.fromList(List.generate(length, (_) => rng.nextInt(256)));

void main() {
  final n = Curve256189Params.n;
  final p = Curve256189Params.p;
  final gEd = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);

  test('group law: (a + b) G == aG + bG on Edwards', () {
    final rng = Random(1);
    for (var i = 0; i < 100; i++) {
      final a = _randomBelow(rng, n);
      final b = _randomBelow(rng, n);
      final sum = TwistedEdwards.add(
        TwistedEdwards.scalarMul(a, gEd),
        TwistedEdwards.scalarMul(b, gEd),
      );
      final direct = TwistedEdwards.scalarMul((a + b) % n, gEd);
      expect(direct.x, sum.x, reason: 'i=$i a=$a b=$b');
      expect(direct.y, sum.y, reason: 'i=$i a=$a b=$b');
    }
  });

  test('sequential Edwards addition matches scalar multiplication', () {
    var acc = gEd;
    for (var k = 2; k <= 300; k++) {
      acc = TwistedEdwards.add(acc, gEd);
      if (k % 25 == 0) {
        final expected = TwistedEdwards.scalarMul(BigInt.from(k), gEd);
        expect(acc.x, expected.x, reason: 'k=$k');
        expect(acc.y, expected.y, reason: 'k=$k');
      }
    }
  });

  test('dual curve addition is complete on random mixed-order points', () {
    final rng = Random(7);
    final order2 = MontgomeryPoint(BigInt.zero, BigInt.zero);
    for (var i = 0; i < 60; i++) {
      final a = _randomBelow(rng, n) + BigInt.one;
      final b = _randomBelow(rng, n) + BigInt.one;
      var p1 = Montgomery.scalarMulFull(a, MontgomeryPoint.G);
      var p2 = Montgomery.scalarMulFull(b, MontgomeryPoint.G);
      if (rng.nextBool()) p1 = Montgomery.add(p1, order2);
      if (rng.nextBool()) p2 = Montgomery.add(p2, order2);

      final expected = TwistedEdwards.fromMontgomery(Montgomery.add(p1, p2));

      final got = TwistedEdwards.add(
        TwistedEdwards.fromMontgomery(p1),
        TwistedEdwards.fromMontgomery(p2),
      );
      expect(got.x, expected.x, reason: 'i=$i');
      expect(got.y, expected.y, reason: 'i=$i');

      final mapped = DualEdwards.toTwistedEdwards(DualEdwards.add(
        DualEdwards.fromMontgomery(p1),
        DualEdwards.fromMontgomery(p2),
      ));
      expect(mapped.x, expected.x, reason: 'i=$i');
      expect(mapped.y, expected.y, reason: 'i=$i');
    }
  });

  test('Phi commutes with scalar multiplication', () {
    final rng = Random(8);
    final phiG = DualEdwards.fromTwistedEdwards(gEd);
    for (var i = 0; i < 10; i++) {
      final k = _randomBelow(rng, n) + BigInt.one;
      final expected =
          DualEdwards.fromTwistedEdwards(TwistedEdwards.scalarMul(k, gEd));
      final got = DualEdwards.scalarMul(k, phiG);
      expect(got.x, expected.x, reason: 'i=$i k=$k');
      expect(got.y, expected.y, reason: 'i=$i k=$k');
    }
  });

  test('blinded ladder agrees with the unblinded ladder', () {
    final rng = Random(2);
    for (var i = 0; i < 50; i++) {
      final k = _randomBelow(rng, n) + BigInt.one;
      expect(
        Montgomery.ladderXOnly(k, MontgomeryPoint.G.x),
        Montgomery.ladderXOnly(k, MontgomeryPoint.G.x, blind: false),
        reason: 'k=$k',
      );
    }
  });

  test('XEdDSA: random keys and messages sign and verify', () {
    final rng = Random(3);
    for (var i = 0; i < 100; i++) {
      final kp = XEdDSA.generateKeyPair(_randomBytes(rng, 32));
      final message = _randomBytes(rng, rng.nextInt(100));
      final sig = XEdDSA.sign(message, kp['privateKey']!);
      expect(XEdDSA.verify(message, sig, kp['publicKey']!), isTrue,
          reason: 'i=$i');
      final other = _randomBytes(rng, 33);
      expect(XEdDSA.verify(other, sig, kp['publicKey']!), isFalse,
          reason: 'i=$i');
    }
  });

  test('X256189: random key pairs agree', () {
    final rng = Random(4);
    for (var i = 0; i < 50; i++) {
      final a = X256189.generateKeyPair(_randomBytes(rng, 32));
      final b = X256189.generateKeyPair(_randomBytes(rng, 32));
      final ab =
          X256189.computeSharedSecret(a['privateKey']!, b['publicKey']!);
      final ba =
          X256189.computeSharedSecret(b['privateKey']!, a['publicKey']!);
      expect(ab, isNotNull);
      expect(ab, ba, reason: 'i=$i');
    }
  });

  test('random public keys: accepted exactly when valid, never throw', () {
    final rng = Random(5);
    final priv = seedFrom(1);
    for (var i = 0; i < 100; i++) {
      final peer = _randomBytes(rng, 32);
      final secret = X256189.computeSharedSecret(priv, peer);
      final x = XEdDSA.decodeLittleEndian(peer);
      expect(secret != null, Montgomery.isValidPublicKeyX(x), reason: 'i=$i');
    }
  });

  test('Edwards decodePoint: random input yields null or an on-curve point', () {
    final rng = Random(6);
    var decoded = 0;
    for (var i = 0; i < 500; i++) {
      final bytes = _randomBytes(rng, 33);
      final point = TwistedEdwards.decodePoint(bytes);
      if (point != null) {
        decoded++;
        expect(TwistedEdwards.isOnCurve(point), isTrue, reason: 'i=$i');
        expect(point.y < p && point.x < p, isTrue);
      }
    }
    expect(decoded, greaterThan(0));
  });

  test('Edwards encode/decode round trip for random multiples of G', () {
    final rng = Random(7);
    for (var i = 0; i < 100; i++) {
      final point =
          TwistedEdwards.scalarMul(_randomBelow(rng, n) + BigInt.one, gEd);
      final back =
          TwistedEdwards.decodePoint(TwistedEdwards.encodePoint(point));
      expect(back, isNotNull, reason: 'i=$i');
      expect(back!.x, point.x);
      expect(back.y, point.y);
    }
  });

  test('Elligator: encode lands on the curve and decode/encode is stable', () {
    final rng = Random(8);
    for (var i = 0; i < 300; i++) {
      final t = _randomBelow(rng, p);
      if (t == BigInt.zero) continue;
      final x = Elligator.encode(t)!;
      expect(Montgomery.yFromX(x), isNotNull, reason: 't=$t');
      final back = Elligator.decode(x);
      if (back != null) {
        expect(back <= (p >> 1), isTrue);
        expect(Elligator.encode(back), x, reason: 't=$t');
      }
    }
  });

  test('Ed256189: random signatures round-trip and tampering fails', () {
    final rng = Random(11);
    for (var i = 0; i < 12; i++) {
      final seed = _randomBytes(rng, 32);
      final message = _randomBytes(rng, rng.nextInt(65));
      final keys = Ed256189.generateKeyPair(seed);
      final signature = Ed256189.sign(message, seed);

      expect(
        Ed256189.verify(message, signature, keys['publicKey']!),
        isTrue,
        reason: 'i=$i',
      );

      final tampered = Uint8List.fromList(signature)..[32] ^= 1;
      expect(
        Ed256189.verify(message, tampered, keys['publicKey']!),
        isFalse,
        reason: 'i=$i',
      );
    }
  });

  test('DualEdwards: encode/decode round trip for random multiples', () {
    final rng = Random(12);
    final gDual = DualEdwards.fromMontgomery(MontgomeryPoint.G);
    for (var i = 0; i < 100; i++) {
      final point = DualEdwards.scalarMul(
        _randomBelow(rng, n) + BigInt.one,
        gDual,
      );
      expect(
        DualEdwards.isInPrimeOrderSubgroup(point),
        isTrue,
        reason: 'i=$i',
      );

      final back = DualEdwards.decodePoint(DualEdwards.encodePoint(point));
      expect(back, isNotNull, reason: 'i=$i');
      expect(back!.x, point.x, reason: 'i=$i');
      expect(back.y, point.y, reason: 'i=$i');
    }
  });
}
