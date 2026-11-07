import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'ed256189_vectors.dart';
import 'helpers.dart';

bool _same(EdwardsPoint a, EdwardsPoint b) => a.x == b.x && a.y == b.y;

BigInt _legendre(BigInt x) => FieldElement.pow(
    x % Curve256189Params.p, (Curve256189Params.p - BigInt.one) >> 1);

bool _isSquare(BigInt x) =>
    x % Curve256189Params.p == BigInt.zero || _legendre(x) == BigInt.one;

Uint8List _pointEncoding(BigInt v, int parity) =>
    Uint8List.fromList([...encodeLE32(v), parity]);

Uint8List _replaceR(Uint8List signature, Uint8List rEncoding) =>
    Uint8List.fromList([...rEncoding, ...signature.sublist(33)]);

Uint8List _replaceS(Uint8List signature, BigInt s) =>
    Uint8List.fromList([...signature.sublist(0, 33), ...encodeLE32(s)]);

void main() {
  final p = Curve256189Params.p;
  final n = Curve256189Params.n;
  final gDual = DualEdwards.fromMontgomery(MontgomeryPoint.G);
  final identity = EdwardsPoint.infinity();
  final order2 = EdwardsPoint(
    BigInt.zero,
    FieldElement.sub(BigInt.zero, BigInt.one),
  );

  // The two order-4 points of E_{d,a} have v = 0; their u-coordinates are
  // the two square roots of 1/a.
  final order4Even = DualEdwards.decodePoint(_pointEncoding(BigInt.zero, 0))!;
  final order4Odd = DualEdwards.decodePoint(_pointEncoding(BigInt.zero, 1))!;

  group('parameter set', () {
    test('E_{d,a} has a square a and a non-square d', () {
      expect(DualEdwards.a, TwistedEdwards.d);
      expect(DualEdwards.d, TwistedEdwards.a);
      expect(_isSquare(DualEdwards.a), isTrue);
      expect(_isSquare(DualEdwards.d), isFalse);
    });

    test('the signature generator lies on E_{d,a} and has order n', () {
      expect(DualEdwards.isOnCurve(gDual), isTrue);
      expect(DualEdwards.scalarMul(n, gDual).isIdentity, isTrue);
      expect(DualEdwards.scalarMul(n + BigInt.one, gDual).x, gDual.x);
      expect(DualEdwards.scalarMul(n + BigInt.one, gDual).y, gDual.y);
    });

    test('Phi maps the natural Edwards generator to the dual generator', () {
      final natural = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);
      final mapped = DualEdwards.fromTwistedEdwards(natural);
      expect(_same(mapped, gDual), isTrue);
    });

    test('the generator encoding is a known answer', () {
      expect(
        toHex(DualEdwards.encodePoint(gDual)),
        '87a44512042fd91369d0005f710e89a7c6fbd4cb789c555f1a0962af259ebf2e00',
      );
    });
  });

  group('point encoding', () {
    test('encode/decode round-trips subgroup multiples', () {
      for (final k in [
        BigInt.one,
        BigInt.two,
        BigInt.from(3),
        BigInt.from(7),
        n - BigInt.one,
      ]) {
        final point = DualEdwards.scalarMul(k, gDual);
        final decoded = DualEdwards.decodePoint(
          DualEdwards.encodePoint(point),
        );
        expect(decoded, isNotNull);
        expect(_same(decoded!, point), isTrue);
      }
    });

    test('rejects wrong lengths', () {
      expect(DualEdwards.decodePoint(Uint8List(0)), isNull);
      expect(DualEdwards.decodePoint(Uint8List(32)), isNull);
      expect(DualEdwards.decodePoint(Uint8List(34)), isNull);
    });

    test('rejects v >= p', () {
      expect(DualEdwards.decodePoint(_pointEncoding(p, 0)), isNull);
      expect(
        DualEdwards.decodePoint(
          Uint8List.fromList([...List.filled(32, 0xff), 0]),
        ),
        isNull,
      );
    });

    test('rejects parity bytes other than 0 and 1', () {
      final good = DualEdwards.encodePoint(gDual);
      for (final bad in [2, 3, 0x80, 0xff]) {
        final bytes = Uint8List.fromList(good)..[32] = bad;
        expect(DualEdwards.decodePoint(bytes), isNull);
      }
    });

    test('rejects v with no matching u', () {
      // v = 2 gives u^2 = (1 - 4) / (a - 4d), which is not a square.
      expect(DualEdwards.decodePoint(_pointEncoding(BigInt.two, 0)), isNull);
      expect(DualEdwards.decodePoint(_pointEncoding(BigInt.two, 1)), isNull);
    });

    test('handles the identity and the order-2 point', () {
      final decodedIdentity =
          DualEdwards.decodePoint(_pointEncoding(BigInt.one, 0));
      expect(decodedIdentity, isNotNull);
      expect(decodedIdentity!.isIdentity, isTrue);

      // (0, v) is its own negative, so the odd representative is invalid.
      expect(DualEdwards.decodePoint(_pointEncoding(BigInt.one, 1)), isNull);

      final decodedOrder2 =
          DualEdwards.decodePoint(_pointEncoding(p - BigInt.one, 0));
      expect(decodedOrder2, isNotNull);
      expect(_same(decodedOrder2!, order2), isTrue);
    });

    test('handles the order-4 points at v = 0', () {
      expect(DualEdwards.isOnCurve(order4Even), isTrue);
      expect(DualEdwards.isOnCurve(order4Odd), isTrue);
      expect(order4Even.x, FieldElement.sub(BigInt.zero, order4Odd.x));

      final doubled = DualEdwards.scalarMul(BigInt.two, order4Even);
      expect(_same(doubled, order2), isTrue);
      expect(
          DualEdwards.scalarMul(BigInt.from(4), order4Even).isIdentity, isTrue);
    });
  });

  group('subgroup validation', () {
    test('accepts non-identity prime-order points', () {
      expect(DualEdwards.isInPrimeOrderSubgroup(gDual), isTrue);
      for (final k in [BigInt.two, BigInt.from(3), n - BigInt.one]) {
        expect(
          DualEdwards.isInPrimeOrderSubgroup(
            DualEdwards.scalarMul(k, gDual),
          ),
          isTrue,
        );
      }
    });

    test('rejects identity, order-2 and order-4 points', () {
      expect(DualEdwards.isInPrimeOrderSubgroup(identity), isFalse);
      expect(DualEdwards.isInPrimeOrderSubgroup(order2), isFalse);
      expect(DualEdwards.isInPrimeOrderSubgroup(order4Even), isFalse);
      expect(DualEdwards.isInPrimeOrderSubgroup(order4Odd), isFalse);
    });

    test('rejects mixed-order points', () {
      final mixed = DualEdwards.add(gDual, order2);
      expect(DualEdwards.isOnCurve(mixed), isTrue);
      expect(DualEdwards.isInPrimeOrderSubgroup(mixed), isFalse);
    });
  });

  group('key derivation', () {
    test('matches the independent Python vectors', () {
      for (final vector in ed256189Vectors) {
        final seed = fromHex(vector['seed']!);
        expect(
          toHex(Ed256189.publicKeyFromSeed(seed)),
          vector['publicKey'],
          reason: vector['name'],
        );
        expect(
          toHex(Ed256189.generateKeyPair(seed)['publicKey']!),
          vector['publicKey'],
          reason: vector['name'],
        );
      }
    });

    test('returns a copy of the seed', () {
      final seed = seedFrom(0);
      final keys = Ed256189.generateKeyPair(seed);
      seed[0] ^= 0xff;
      expect(keys['privateKey']![0], 0);
    });

    test('rejects seeds that are not 32 bytes', () {
      for (final length in [0, 31, 33]) {
        expect(
          () => Ed256189.generateKeyPair(Uint8List(length)),
          throwsArgumentError,
        );
        expect(
          () => Ed256189.publicKeyFromSeed(Uint8List(length)),
          throwsArgumentError,
        );
        expect(
          () => Ed256189.sign(Uint8List(1), Uint8List(length)),
          throwsArgumentError,
        );
      }
    });
  });

  group('sign and verify', () {
    test('matches the independent Python vectors', () {
      for (final vector in ed256189Vectors) {
        final seed = fromHex(vector['seed']!);
        final message = fromHex(vector['message']!);
        final publicKey = fromHex(vector['publicKey']!);

        final signature = Ed256189.sign(message, seed);
        expect(toHex(signature), vector['signature'], reason: vector['name']);
        expect(signature.length, Ed256189.signatureLength);
        expect(publicKey.length, Ed256189.publicKeyLength);
        expect(
          Ed256189.verify(message, signature, publicKey),
          isTrue,
          reason: vector['name'],
        );
      }
    });

    test('signing is deterministic', () {
      final seed = seedFrom(11);
      final message = bytesOf('deterministic');
      expect(
        toHex(Ed256189.sign(message, seed)),
        toHex(Ed256189.sign(message, seed)),
      );
    });

    test('different messages give different signatures', () {
      final seed = seedFrom(12);
      final a = Ed256189.sign(bytesOf('message a'), seed);
      final b = Ed256189.sign(bytesOf('message b'), seed);
      expect(toHex(a), isNot(toHex(b)));
    });

    test('challengeFor is deterministic and canonical', () {
      final r = fromHex(ed256189Vectors.first['signature']!).sublist(0, 33);
      final pk = fromHex(ed256189Vectors.first['publicKey']!);
      final message = fromHex(ed256189Vectors.first['message']!);

      final k1 = Ed256189.challengeFor(r, pk, message);
      final k2 = Ed256189.challengeFor(r, pk, message);
      expect(k1, k2);
      expect(k1 >= BigInt.zero && k1 < n, isTrue);
    });

    test('challengeFor rejects wrong lengths', () {
      final r = Uint8List(33);
      final pk = Uint8List(33);
      expect(() => Ed256189.challengeFor(Uint8List(32), pk, Uint8List(0)),
          throwsArgumentError);
      expect(() => Ed256189.challengeFor(r, Uint8List(32), Uint8List(0)),
          throwsArgumentError);
    });
  });

  group('verification rejects malformed inputs', () {
    late Uint8List seed;
    late Uint8List message;
    late Uint8List publicKey;
    late Uint8List signature;

    setUp(() {
      final vector = ed256189Vectors.first;
      seed = fromHex(vector['seed']!);
      message = fromHex(vector['message']!);
      publicKey = fromHex(vector['publicKey']!);
      signature = Ed256189.sign(message, seed);
    });

    test('wrong lengths', () {
      expect(Ed256189.verify(message, Uint8List(64), publicKey), isFalse);
      expect(Ed256189.verify(message, Uint8List(66), publicKey), isFalse);
      expect(Ed256189.verify(message, signature, Uint8List(32)), isFalse);
      expect(Ed256189.verify(message, signature, Uint8List(34)), isFalse);
    });

    test('tampered message', () {
      final tampered = Uint8List.fromList([...message, ...bytesOf('!')]);
      expect(Ed256189.verify(tampered, signature, publicKey), isFalse);
    });

    test('flipped R sign bit', () {
      final flipped = Uint8List.fromList(signature)..[32] ^= 1;
      expect(Ed256189.verify(message, flipped, publicKey), isFalse);
    });

    test('flipped S bit', () {
      final flipped = Uint8List.fromList(signature)..[40] ^= 1;
      expect(Ed256189.verify(message, flipped, publicKey), isFalse);
    });

    test('non-canonical S', () {
      expect(
        Ed256189.verify(message, _replaceS(signature, n), publicKey),
        isFalse,
      );
      expect(
        Ed256189.verify(
            message, _replaceS(signature, n + BigInt.one), publicKey),
        isFalse,
      );
    });

    test('low-order R', () {
      for (final point in [identity, order2, order4Even, order4Odd]) {
        final bad = _replaceR(signature, DualEdwards.encodePoint(point));
        expect(Ed256189.verify(message, bad, publicKey), isFalse);
      }
    });

    test('low-order and mixed-order public keys', () {
      final mixed = DualEdwards.add(gDual, order2);
      for (final point in [identity, order2, order4Even, order4Odd, mixed]) {
        final badKey = DualEdwards.encodePoint(point);
        expect(Ed256189.verify(message, signature, badKey), isFalse);
      }
    });

    test('flipped public-key sign bit', () {
      final flipped = Uint8List.fromList(publicKey)..[32] ^= 1;
      expect(Ed256189.verify(message, signature, flipped), isFalse);
    });

    test('non-canonical point encodings', () {
      final badV = _pointEncoding(p, 0);
      expect(
        Ed256189.verify(message, _replaceR(signature, badV), publicKey),
        isFalse,
      );
      expect(Ed256189.verify(message, signature, badV), isFalse);

      final badParity = Uint8List.fromList(publicKey)..[32] = 2;
      expect(Ed256189.verify(message, signature, badParity), isFalse);
    });

    test('random 65-byte signatures and 33-byte keys never throw', () {
      final rng = Random(9);
      for (var i = 0; i < 25; i++) {
        final randomSignature = Uint8List.fromList(
          List.generate(65, (_) => rng.nextInt(256)),
        );
        final randomKey = Uint8List.fromList(
          List.generate(33, (_) => rng.nextInt(256)),
        );
        final randomMessage = Uint8List.fromList(
          List.generate(7, (_) => rng.nextInt(256)),
        );
        expect(
          () => Ed256189.verify(
            randomMessage,
            randomSignature,
            randomKey,
          ),
          returnsNormally,
        );
      }
    });
  });

  group('protocol separation', () {
    test('Ed256189 signatures are not XEdDSA signatures', () {
      final seed = seedFrom(21);
      final message = bytesOf('cross protocol');
      final edSignature = Ed256189.sign(message, seed);
      final xeddsaKey = XEdDSA.generateKeyPair(seed)['publicKey']!;

      // Different length is rejected immediately, but the distinct domain
      // strings mean that even matching-length transcripts cannot collide.
      expect(Ed256189.verify(message, edSignature, xeddsaKey), isFalse);
      expect(XEdDSA.verify(message, edSignature, xeddsaKey), isFalse);
    });

    test('the challenge differs from an unseparated hash', () {
      final r = Uint8List(33);
      final pk = Uint8List(33);
      final message = bytesOf('domain');
      final k = Ed256189.challengeFor(r, pk, message);

      // A challenge computed without the Ed256189 domain must differ.
      final digest = sha512.convert([...message]).bytes;
      var plain = BigInt.zero;
      for (var i = digest.length - 1; i >= 0; i--) {
        plain = (plain << 8) | BigInt.from(digest[i]);
      }
      expect(k, isNot(plain % n));
    });
  });
}
