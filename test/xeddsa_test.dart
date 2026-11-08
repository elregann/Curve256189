import 'dart:math';
import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';
import 'xeddsa_vectors.dart';

void main() {
  final n = Curve256189Params.n;
  final p = Curve256189Params.p;

  final seed = seedFrom(1);
  final keyPair = XEdDSA.generateKeyPair(seed);
  final privateKey = keyPair['privateKey']!;
  final publicKey = keyPair['publicKey']!;
  final message = bytesOf('Hello Curve256189!');
  final signature = XEdDSA.sign(message, privateKey);

  Uint8List withSignature(Uint8List r, Uint8List s) =>
      Uint8List.fromList([...r, ...s]);

  group('key generation', () {
    test('published public key, equal to the X256189 key', () {
      expect(toHex(publicKey),
          '337d3142bff70cdcbe04d69ee7b7a36c3e8df6bba0a5e0a12cb4b1b580bab424');
      expect(publicKey, X256189.generateKeyPair(seed)['publicKey']);
    });

    test('seed must be 32 bytes', () {
      expect(() => XEdDSA.generateKeyPair(Uint8List(31)), throwsArgumentError);
      expect(() => XEdDSA.generateKeyPair(Uint8List(33)), throwsArgumentError);
      expect(() => XEdDSA.sign(message, Uint8List(31)), throwsArgumentError);
      expect(
          () => XEdDSA.publicKeyFromSeed(Uint8List(31)), throwsArgumentError);
      expect(
          () => XEdDSA.publicKeyFromSeed(Uint8List(33)), throwsArgumentError);
    });

    test('publicKeyFromSeed matches generateKeyPair and X256189', () {
      expect(XEdDSA.publicKeyFromSeed(seed), publicKey);
      expect(XEdDSA.publicKeyFromSeed(seed),
          X256189.generateKeyPair(seed)['publicKey']);
    });
  });

  group('independent vectors', () {
    test('16 vectors from the Python reference', () {
      expect(xeddsaVectors, hasLength(16));

      for (final vector in xeddsaVectors) {
        final name = vector['name']!;
        final vectorSeed = fromHex(vector['seed']!);
        final vectorMessage = fromHex(vector['message']!);
        final vectorPublicKey = fromHex(vector['publicKey']!);
        final vectorSignature = fromHex(vector['signature']!);

        expect(toHex(XEdDSA.publicKeyFromSeed(vectorSeed)), vector['publicKey'],
            reason: name);
        expect(toHex(XEdDSA.generateKeyPair(vectorSeed)['publicKey']!),
            vector['publicKey'],
            reason: name);
        expect(toHex(X256189.generateKeyPair(vectorSeed)['publicKey']!),
            vector['publicKey'],
            reason: name);
        expect(
            toHex(XEdDSA.sign(vectorMessage, vectorSeed)), vector['signature'],
            reason: name);
        expect(XEdDSA.verify(vectorMessage, vectorSignature, vectorPublicKey),
            isTrue,
            reason: name);
      }
    });
  });

  group('sign', () {
    test('published signature vector', () {
      expect(
        toHex(signature),
        'c87e2d535cab5c2ede5993907c4c8d97aa6be84dd9de5b0b4b39e56d4d084284'
        'ee7a80cfbff274f44f74b7a03b49b744c481f702a80c35a93ff03ad11cef142e',
      );
    });

    test('64 bytes and deterministic', () {
      expect(signature.length, XEdDSA.signatureLength);
      expect(XEdDSA.sign(message, privateKey), signature);
    });

    test('different messages give different signatures', () {
      expect(XEdDSA.sign(bytesOf('Hello Curve256189?'), privateKey),
          isNot(signature));
    });

    test('s is a canonical scalar below n', () {
      final s = XEdDSA.decodeLittleEndian(signature.sublist(32));
      expect(s < n, isTrue);
    });
  });

  group('verify', () {
    test('valid signature verifies', () {
      expect(XEdDSA.verify(message, signature, publicKey), isTrue);
    });

    test('empty, short and long messages', () {
      for (final m in [Uint8List(0), Uint8List(1), Uint8List(1000)]) {
        final sig = XEdDSA.sign(m, privateKey);
        expect(XEdDSA.verify(m, sig, publicKey), isTrue,
            reason: 'len=${m.length}');
      }
    });

    test('several keys and messages', () {
      for (var i = 0; i < 10; i++) {
        final kp = XEdDSA.generateKeyPair(seedFrom(i * 13));
        final m = bytesOf('message number $i');
        final sig = XEdDSA.sign(m, kp['privateKey']!);
        expect(XEdDSA.verify(m, sig, kp['publicKey']!), isTrue, reason: 'i=$i');
      }
    });

    test('wrong message is rejected', () {
      expect(XEdDSA.verify(bytesOf('Hello Curve256189?'), signature, publicKey),
          isFalse);
    });

    test('wrong public key is rejected', () {
      final other = XEdDSA.generateKeyPair(seedFrom(2));
      expect(XEdDSA.verify(message, signature, other['publicKey']!), isFalse);
    });

    test('flipping any single bit of the signature is rejected', () {
      for (var byte = 0; byte < 64; byte += 3) {
        final bad = Uint8List.fromList(signature);
        bad[byte] ^= 0x01;
        expect(XEdDSA.verify(message, bad, publicKey), isFalse,
            reason: 'byte=$byte');
      }
    });

    test('random signatures are rejected', () {
      final rng = Random(7);
      for (var i = 0; i < 50; i++) {
        final fake =
            Uint8List.fromList(List.generate(64, (_) => rng.nextInt(256)));
        expect(XEdDSA.verify(message, fake, publicKey), isFalse);
      }
    });

    test('a signature is not valid under a different key and message', () {
      final other = XEdDSA.generateKeyPair(seedFrom(200));
      final otherSig = XEdDSA.sign(message, other['privateKey']!);
      expect(XEdDSA.verify(message, otherSig, publicKey), isFalse);
      expect(XEdDSA.verify(message, otherSig, other['publicKey']!), isTrue);
    });
  });

  group('malleability', () {
    final xR = signature.sublist(0, 32);
    final s = XEdDSA.decodeLittleEndian(signature.sublist(32));

    test('(x(R), n - s) is rejected', () {
      final sig = withSignature(xR, XEdDSA.encodeScalar((n - s) % n));
      expect(XEdDSA.verify(message, sig, publicKey), isFalse);
    });

    test('(x(R), s + n) is rejected as non-canonical', () {
      final sig = withSignature(xR, encodeLE32(s + n));
      expect(XEdDSA.verify(message, sig, publicKey), isFalse);
    });

    test('s = 0 and s = n are rejected', () {
      expect(
          XEdDSA.verify(message, withSignature(xR, Uint8List(32)), publicKey),
          isFalse);
      expect(
          XEdDSA.verify(message, withSignature(xR, encodeLE32(n)), publicKey),
          isFalse);
    });
  });

  group('encoding and invalid inputs', () {
    test('wrong signature and public key lengths', () {
      expect(
          XEdDSA.verify(message, signature.sublist(0, 63), publicKey), isFalse);
      expect(
          XEdDSA.verify(
              message, Uint8List.fromList([...signature, 0]), publicKey),
          isFalse);
      expect(
          XEdDSA.verify(message, signature, publicKey.sublist(0, 31)), isFalse);
      expect(
          XEdDSA.verify(
              message, signature, Uint8List.fromList([...publicKey, 0])),
          isFalse);
      expect(XEdDSA.verify(message, Uint8List(0), publicKey), isFalse);
    });

    test('low-order and mixed-order public keys', () {
      expect(XEdDSA.verify(message, signature, Uint8List(32)), isFalse);
      expect(XEdDSA.verify(message, signature, encodeLE32(p - BigInt.one)),
          isFalse);
      final mixed = Montgomery.add(
          MontgomeryPoint.G, MontgomeryPoint(BigInt.zero, BigInt.zero));
      expect(XEdDSA.verify(message, signature, encodeLE32(mixed.x)), isFalse);
    });

    test('low-order R', () {
      final sBytes = signature.sublist(32);
      expect(
          XEdDSA.verify(
              message, withSignature(Uint8List(32), sBytes), publicKey),
          isFalse);
      expect(
          XEdDSA.verify(message,
              withSignature(encodeLE32(p - BigInt.one), sBytes), publicKey),
          isFalse);
    });

    test('x >= p in R or in the public key', () {
      final sBytes = signature.sublist(32);
      expect(
          XEdDSA.verify(
              message, withSignature(encodeLE32(p), sBytes), publicKey),
          isFalse);
      expect(XEdDSA.verify(message, signature, encodeLE32(p)), isFalse);
    });

    test('all-zero signature', () {
      expect(XEdDSA.verify(message, Uint8List(64), publicKey), isFalse);
    });

    test('non-square x-coordinate is rejected', () {
      // x = 3 has a non-square right-hand side on this curve.
      final x3 = encodeLE32(BigInt.from(3));
      expect(
          XEdDSA.verify(
              message, withSignature(x3, signature.sublist(32)), publicKey),
          isFalse);
      expect(XEdDSA.verify(message, signature, x3), isFalse);
    });

    test('x = p + 1 is rejected', () {
      final xp1 = encodeLE32(p + BigInt.one);
      expect(
          XEdDSA.verify(
              message, withSignature(xp1, signature.sublist(32)), publicKey),
          isFalse);
      expect(XEdDSA.verify(message, signature, xp1), isFalse);
    });

    test('random signatures and public keys never throw', () {
      final rng = Random(11);
      for (var i = 0; i < 50; i++) {
        final sig =
            Uint8List.fromList(List.generate(64, (_) => rng.nextInt(256)));
        final pk =
            Uint8List.fromList(List.generate(32, (_) => rng.nextInt(256)));
        expect(XEdDSA.verify(message, sig, pk), isFalse, reason: 'i=$i');
      }
    });
  });

  group('protocol separation', () {
    test('Ed256189 signatures are not XEdDSA signatures', () {
      final edKeyPair = Ed256189.generateKeyPair(seed);
      final edSignature = Ed256189.sign(message, edKeyPair['privateKey']!);

      expect(Ed256189.verify(message, edSignature, edKeyPair['publicKey']!),
          isTrue);
      expect(XEdDSA.verify(message, edSignature, edKeyPair['publicKey']!),
          isFalse);
    });

    test('XEdDSA signatures are not Ed256189 signatures', () {
      expect(Ed256189.verify(message, signature, publicKey), isFalse);
    });
  });

  group('helpers', () {
    test('encodeScalar range', () {
      expect(() => XEdDSA.encodeScalar(-BigInt.one), throwsArgumentError);
      expect(() => XEdDSA.encodeScalar(n), throwsArgumentError);
      expect(XEdDSA.encodeScalar(BigInt.zero), Uint8List(32));
    });

    test('little-endian round trip', () {
      final v = big('123456789012345678901234567890');
      expect(XEdDSA.decodeLittleEndian(encodeLE32(v)), v);
    });

    test('challengeFor validates lengths and is deterministic', () {
      final h1 =
          XEdDSA.challengeFor(signature.sublist(0, 32), publicKey, message);
      final h2 =
          XEdDSA.challengeFor(signature.sublist(0, 32), publicKey, message);
      expect(h1, h2);
      expect(h1 < n, isTrue);
      expect(() => XEdDSA.challengeFor(Uint8List(31), publicKey, message),
          throwsArgumentError);
      expect(() => XEdDSA.challengeFor(Uint8List(32), Uint8List(33), message),
          throwsArgumentError);
    });
  });

  test('ECDH secret can be signed together with a message', () {
    final bob = X256189.generateKeyPair(seedFrom(33));
    final shared = X256189.computeSharedSecret(privateKey, bob['publicKey']!)!;
    final combined = Uint8List.fromList([...shared, ...message]);
    final sig = XEdDSA.sign(combined, privateKey);
    expect(XEdDSA.verify(combined, sig, publicKey), isTrue);
  });
}
