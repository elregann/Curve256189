import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

SignatureBundle _bundle(int seedOffset, String message) {
  final kp = XEdDSA.generateKeyPair(seedFrom(seedOffset));
  final msg = bytesOf(message);
  return SignatureBundle(
    message: msg,
    signature: XEdDSA.sign(msg, kp['privateKey']!),
    publicKey: kp['publicKey']!,
  );
}

SignatureBundle _with(
  SignatureBundle b, {
  Uint8List? message,
  Uint8List? signature,
  Uint8List? publicKey,
}) =>
    SignatureBundle(
      message: message ?? b.message,
      signature: signature ?? b.signature,
      publicKey: publicKey ?? b.publicKey,
    );

void main() {
  final n = Curve256189Params.n;
  final b1 = _bundle(1, 'Hello Curve256189!');
  final b2 = _bundle(33, 'Batch verification');
  final b3 = _bundle(65, 'Third message');

  group('valid input', () {
    test('empty batch is accepted', () {
      expect(BatchVerify.verify([]), isTrue);
    });

    test('single signature', () {
      expect(BatchVerify.verify([b1]), isTrue);
      final bad = _with(b1, message: bytesOf('other'));
      expect(BatchVerify.verify([bad]), isFalse);
    });

    test('two and five signatures', () {
      expect(BatchVerify.verify([b1, b2]), isTrue);
      final five = List.generate(5, (i) => _bundle(i * 32 + 1, 'Message $i'));
      expect(BatchVerify.verify(five), isTrue);
    });

    test('same signer, many messages', () {
      final bundles = List.generate(4, (i) {
        final kp = XEdDSA.generateKeyPair(seedFrom(9));
        final msg = bytesOf('same signer $i');
        return SignatureBundle(
          message: msg,
          signature: XEdDSA.sign(msg, kp['privateKey']!),
          publicKey: kp['publicKey']!,
        );
      });
      expect(BatchVerify.verify(bundles), isTrue);
    });

    test('agrees with individual verification', () {
      final ten = List.generate(10, (i) => _bundle(i * 7 + 1, 'Command $i'));
      expect(
          ten.every((b) => XEdDSA.verify(b.message, b.signature, b.publicKey)),
          isTrue);
      expect(BatchVerify.verify(ten), isTrue);
    });
  });

  group('one bad entry makes the batch fail', () {
    test('tampered signature, at any position', () {
      final tampered = Uint8List.fromList(b1.signature)..[40] ^= 0x01;
      final bad = _with(b1, signature: tampered);
      expect(BatchVerify.verify([bad, b2, b3]), isFalse);
      expect(BatchVerify.verify([b2, bad, b3]), isFalse);
      expect(BatchVerify.verify([b2, b3, bad]), isFalse);
    });

    test('tampered R', () {
      final tampered = Uint8List.fromList(b1.signature)..[0] ^= 0x01;
      expect(BatchVerify.verify([_with(b1, signature: tampered), b2]), isFalse);
    });

    test('wrong message and wrong public key', () {
      expect(
          BatchVerify.verify(
              [_with(b1, message: bytesOf('Wrong message!')), b2]),
          isFalse);
      expect(BatchVerify.verify([_with(b1, publicKey: b2.publicKey), b2]),
          isFalse);
    });

    test('swapped signatures between signers', () {
      expect(
        BatchVerify.verify([
          _with(b1, signature: b2.signature),
          _with(b2, signature: b1.signature),
        ]),
        isFalse,
      );
    });

    test('duplicated valid bundle is still valid', () {
      expect(BatchVerify.verify([b1, b1]), isTrue);
    });
  });

  group('malformed entries', () {
    final xR = b1.signature.sublist(0, 32);
    final s = XEdDSA.decodeLittleEndian(b1.signature.sublist(32));

    test('(x(R), n - s)', () {
      final sig =
          Uint8List.fromList([...xR, ...XEdDSA.encodeScalar((n - s) % n)]);
      expect(BatchVerify.verify([_with(b1, signature: sig), b2]), isFalse);
    });

    test('(x(R), s + n)', () {
      final sig = Uint8List.fromList([...xR, ...encodeLE32(s + n)]);
      expect(BatchVerify.verify([_with(b1, signature: sig), b2]), isFalse);
    });

    test('wrong lengths', () {
      expect(
          BatchVerify.verify(
              [_with(b1, signature: b1.signature.sublist(0, 63)), b2]),
          isFalse);
      expect(
          BatchVerify.verify([
            _with(b1, signature: Uint8List.fromList([...b1.signature, 0])),
            b2
          ]),
          isFalse);
      expect(
          BatchVerify.verify(
              [_with(b1, publicKey: b1.publicKey.sublist(0, 31)), b2]),
          isFalse);
    });

    test('low-order public key and low-order R', () {
      expect(BatchVerify.verify([_with(b1, publicKey: Uint8List(32)), b2]),
          isFalse);
      final lowR =
          Uint8List.fromList([...Uint8List(32), ...b1.signature.sublist(32)]);
      expect(BatchVerify.verify([_with(b1, signature: lowR), b2]), isFalse);
    });

    test('mixed-order public key', () {
      final mixed = Montgomery.add(
        MontgomeryPoint.G,
        MontgomeryPoint(BigInt.zero, BigInt.zero),
      );
      expect(
        BatchVerify.verify([
          _with(b1, publicKey: encodeLE32(mixed.x)),
          b2,
        ]),
        isFalse,
      );
    });

    test('all-zero signature', () {
      expect(BatchVerify.verify([_with(b1, signature: Uint8List(64)), b2]),
          isFalse);
    });
  });

  group('batch and individual agree', () {
    final valid = [b1, b2, b3];
    final s1 = XEdDSA.decodeLittleEndian(b1.signature.sublist(32));

    final variants = <String, SignatureBundle>{
      'valid': b1,
      'wrong message': _with(b1, message: bytesOf('Wrong message!')),
      'tampered signature': _with(
        b1,
        signature: Uint8List.fromList(b1.signature)..[7] ^= 0x04,
      ),
      'wrong public key': _with(b1, publicKey: b2.publicKey),
      's >= n': _with(
        b1,
        signature: Uint8List.fromList([
          ...b1.signature.sublist(0, 32),
          ...encodeLE32(s1 + n),
        ]),
      ),
      'low-order public key': _with(b1, publicKey: Uint8List(32)),
      'low-order R': _with(
        b1,
        signature: Uint8List.fromList([
          ...Uint8List(32),
          ...b1.signature.sublist(32),
        ]),
      ),
      'short signature': _with(b1, signature: b1.signature.sublist(0, 63)),
    };

    for (final entry in variants.entries) {
      for (var position = 0; position < valid.length; position++) {
        test('${entry.key} at position $position', () {
          final batch = List<SignatureBundle>.from(valid);
          batch[position] = entry.value;

          final individual = batch.every(
            (b) => XEdDSA.verify(b.message, b.signature, b.publicKey),
          );
          expect(BatchVerify.verify(batch), individual,
              reason: '${entry.key} at position $position');
        });
      }
    }
  });

  group('scale and stability', () {
    test('large batch of 20 signatures', () {
      final twenty = List.generate(20, (i) => _bundle(i * 3 + 1, 'Large $i'));

      expect(
        twenty.every(
          (b) => XEdDSA.verify(b.message, b.signature, b.publicKey),
        ),
        isTrue,
      );
      expect(BatchVerify.verify(twenty), isTrue);

      final bad = List<SignatureBundle>.from(twenty);
      bad[13] = _with(bad[13], message: bytesOf('tampered'));
      expect(BatchVerify.verify(bad), isFalse);
    });

    test('repeated randomized runs are stable', () {
      for (var i = 0; i < 5; i++) {
        expect(BatchVerify.verify([b1, b2, b3]), isTrue, reason: 'run=$i');
      }

      final tampered = _with(
        b1,
        signature: Uint8List.fromList(b1.signature)..[0] ^= 0x01,
      );
      for (var i = 0; i < 5; i++) {
        expect(BatchVerify.verify([tampered, b2, b3]), isFalse,
            reason: 'run=$i');
      }
    });
  });
}
