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
      expect(ten.every((b) => XEdDSA.verify(b.message, b.signature, b.publicKey)),
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
          BatchVerify.verify([_with(b1, message: bytesOf('Wrong message!')), b2]),
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
      final sig = Uint8List.fromList([...xR, ...XEdDSA.encodeScalar((n - s) % n)]);
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
      final lowR = Uint8List.fromList([...Uint8List(32), ...b1.signature.sublist(32)]);
      expect(BatchVerify.verify([_with(b1, signature: lowR), b2]), isFalse);
    });

    test('all-zero signature', () {
      expect(BatchVerify.verify([_with(b1, signature: Uint8List(64)), b2]),
          isFalse);
    });
  });
}
