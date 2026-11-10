import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  final p = Curve256189Params.p;
  final aliceSeed = seedFrom(1);
  final bobSeed = seedFrom(33);
  final alice = X256189.generateKeyPair(aliceSeed);
  final bob = X256189.generateKeyPair(bobSeed);

  group('key generation', () {
    test('published test vectors', () {
      expect(toHex(alice['publicKey']!),
          'b1b998018648e7195a06c1b8c6bd029c84d384be33673c010f83a960a1160275');
      expect(toHex(bob['publicKey']!),
          '62bd3d3f9ccf01644be90c04884effff0e1198187a6d11731a9b53ff0bf0467c');
    });

    test('private key is the seed, public key is 32 bytes', () {
      expect(alice['privateKey'], aliceSeed);
      expect(alice['publicKey']!.length, 32);
    });

    test('deterministic and seed-dependent', () {
      expect(X256189.generateKeyPair(aliceSeed)['publicKey'],
          alice['publicKey']);
      expect(alice['publicKey'], isNot(bob['publicKey']));
    });

    test('public key is a valid prime-order x-coordinate', () {
      final x = XEdDSA.decodeLittleEndian(alice['publicKey']!);
      expect(Montgomery.isValidPublicKeyX(x), isTrue);
    });

    test('seed must be 32 bytes', () {
      expect(() => X256189.generateKeyPair(Uint8List(31)), throwsArgumentError);
      expect(() => X256189.generateKeyPair(Uint8List(33)), throwsArgumentError);
      expect(() => X256189.generateKeyPair(Uint8List(0)), throwsArgumentError);
    });
  });

  group('shared secret', () {
    test('both sides agree and match the published vector', () {
      final ab = X256189.computeSharedSecret(
          alice['privateKey']!, bob['publicKey']!);
      final ba = X256189.computeSharedSecret(
          bob['privateKey']!, alice['publicKey']!);
      expect(ab, isNotNull);
      expect(ba, isNotNull);
      expect(ab, ba);
      expect(ab!.length, 32);
      expect(toHex(ab),
          '49dc0d93c74668da52553c6d981e60996b7bc9fae0930bedcc3e4e67bf57da86');
    });

    test('shared secret is repeatable despite scalar blinding', () {
      final first = X256189.computeSharedSecret(
          alice['privateKey']!, bob['publicKey']!);
      for (var i = 0; i < 3; i++) {
        expect(
            X256189.computeSharedSecret(
                alice['privateKey']!, bob['publicKey']!),
            first);
      }
    });

    test('different peers give different secrets', () {
      final carol = X256189.generateKeyPair(seedFrom(77));
      expect(
        X256189.computeSharedSecret(alice['privateKey']!, bob['publicKey']!),
        isNot(X256189.computeSharedSecret(
            alice['privateKey']!, carol['publicKey']!)),
      );
    });

    test('three-party symmetry: a(bG) == b(aG) for several seeds', () {
      for (var i = 0; i < 5; i++) {
        final a = X256189.generateKeyPair(seedFrom(10 + i));
        final b = X256189.generateKeyPair(seedFrom(100 + i));
        expect(
          X256189.computeSharedSecret(a['privateKey']!, b['publicKey']!),
          X256189.computeSharedSecret(b['privateKey']!, a['publicKey']!),
        );
      }
    });
  });

  group('invalid public keys are rejected', () {
    Uint8List? agree(Uint8List peer) =>
        X256189.computeSharedSecret(alice['privateKey']!, peer);

    test('wrong lengths', () {
      expect(agree(Uint8List(0)), isNull);
      expect(agree(alice['publicKey']!.sublist(0, 31)), isNull);
      expect(agree(Uint8List.fromList([...bob['publicKey']!, 0])), isNull);
    });

    test('x = 0 (order 2) and x = p - 1 (order 4)', () {
      expect(agree(Uint8List(32)), isNull);
      expect(agree(encodeLE32(p - BigInt.one)), isNull);
    });

    test('x >= p', () {
      expect(agree(encodeLE32(p)), isNull);
      expect(agree(encodeLE32(p + BigInt.one)), isNull);
      expect(agree(Uint8List.fromList(List.filled(32, 0xff))), isNull);
    });

    test('mixed-order point', () {
      final mixed = Montgomery.add(
          MontgomeryPoint.G, MontgomeryPoint(BigInt.zero, BigInt.zero));
      expect(agree(encodeLE32(mixed.x)), isNull);
    });

    test('twist points (x = 1, 4 have no y on the curve)', () {
      for (final x in [1, 4]) {
        expect(agree(encodeLE32(BigInt.from(x))), isNull, reason: 'x=$x');
      }
    });
  });
}
