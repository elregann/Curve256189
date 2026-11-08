import 'dart:math';
import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

BigInt _decodeLE(List<int> bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

Ed256189SignatureBundle _bundle(int seedOffset, String message) {
  final kp = Ed256189.generateKeyPair(seedFrom(seedOffset));
  final msg = bytesOf(message);
  return Ed256189SignatureBundle(
    message: msg,
    signature: Ed256189.sign(msg, kp['privateKey']!),
    publicKey: kp['publicKey']!,
  );
}

Ed256189SignatureBundle _with(
  Ed256189SignatureBundle b, {
  Uint8List? message,
  Uint8List? signature,
  Uint8List? publicKey,
}) =>
    Ed256189SignatureBundle(
      message: message ?? b.message,
      signature: signature ?? b.signature,
      publicKey: publicKey ?? b.publicKey,
    );

void main() {
  final p = Curve256189Params.p;
  final n = Curve256189Params.n;
  final gDual = DualEdwards.fromMontgomery(MontgomeryPoint.G);
  final identity = EdwardsPoint.infinity();
  final order2 = EdwardsPoint(
    BigInt.zero,
    FieldElement.sub(BigInt.zero, BigInt.one),
  );
  final order4Even = DualEdwards.decodePoint(
    Uint8List.fromList([...encodeLE32(BigInt.zero), 0]),
  )!;
  final order4Odd = DualEdwards.decodePoint(
    Uint8List.fromList([...encodeLE32(BigInt.zero), 1]),
  )!;

  final b1 = _bundle(1, 'Hello Curve256189!');
  final b2 = _bundle(33, 'Batch verification');
  final b3 = _bundle(65, 'Third message');

  group('valid input', () {
    test('empty batch is accepted', () {
      expect(Ed256189BatchVerify.verify([]), isTrue);
    });

    test('single signature', () {
      expect(Ed256189BatchVerify.verify([b1]), isTrue);
      final bad = _with(b1, message: bytesOf('other'));
      expect(Ed256189BatchVerify.verify([bad]), isFalse);
    });

    test('two and five signatures', () {
      expect(Ed256189BatchVerify.verify([b1, b2]), isTrue);
      final five = List.generate(5, (i) => _bundle(i * 32 + 1, 'Message $i'));
      expect(Ed256189BatchVerify.verify(five), isTrue);
    });

    test('same signer, many messages', () {
      final bundles = List.generate(4, (i) {
        final kp = Ed256189.generateKeyPair(seedFrom(9));
        final msg = bytesOf('same signer $i');
        return Ed256189SignatureBundle(
          message: msg,
          signature: Ed256189.sign(msg, kp['privateKey']!),
          publicKey: kp['publicKey']!,
        );
      });
      expect(Ed256189BatchVerify.verify(bundles), isTrue);
    });

    test('agrees with individual verification', () {
      final ten = List.generate(10, (i) => _bundle(i * 7 + 1, 'Command $i'));
      expect(
        ten.every(
          (b) => Ed256189.verify(b.message, b.signature, b.publicKey),
        ),
        isTrue,
      );
      expect(Ed256189BatchVerify.verify(ten), isTrue);
    });
  });

  group('one bad entry makes the batch fail', () {
    test('tampered signature, at any position', () {
      final tampered = Uint8List.fromList(b1.signature)..[40] ^= 0x01;
      final bad = _with(b1, signature: tampered);
      expect(Ed256189BatchVerify.verify([bad, b2, b3]), isFalse);
      expect(Ed256189BatchVerify.verify([b2, bad, b3]), isFalse);
      expect(Ed256189BatchVerify.verify([b2, b3, bad]), isFalse);
    });

    test('tampered R', () {
      final tampered = Uint8List.fromList(b1.signature)..[0] ^= 0x01;
      expect(
        Ed256189BatchVerify.verify([_with(b1, signature: tampered), b2]),
        isFalse,
      );
    });

    test('wrong message and wrong public key', () {
      expect(
        Ed256189BatchVerify.verify(
          [_with(b1, message: bytesOf('Wrong message!')), b2],
        ),
        isFalse,
      );
      expect(
        Ed256189BatchVerify.verify([_with(b1, publicKey: b2.publicKey), b2]),
        isFalse,
      );
    });

    test('swapped signatures between signers', () {
      expect(
        Ed256189BatchVerify.verify([
          _with(b1, signature: b2.signature),
          _with(b2, signature: b1.signature),
        ]),
        isFalse,
      );
    });

    test('duplicated valid bundle is still valid', () {
      expect(Ed256189BatchVerify.verify([b1, b1]), isTrue);
    });
  });

  group('malformed entries', () {
    final r = b1.signature.sublist(0, 33);
    final s = _decodeLE(b1.signature.sublist(33));

    Uint8List withSignature(Uint8List rBytes, BigInt scalar) =>
        Uint8List.fromList([...rBytes, ...encodeLE32(scalar)]);

    test('(R, n - S)', () {
      expect(
        Ed256189BatchVerify.verify(
          [_with(b1, signature: withSignature(r, (n - s) % n)), b2],
        ),
        isFalse,
      );
    });

    test('(R, S + n)', () {
      expect(
        Ed256189BatchVerify.verify(
          [_with(b1, signature: withSignature(r, s + n)), b2],
        ),
        isFalse,
      );
    });

    test('wrong lengths', () {
      expect(
        Ed256189BatchVerify.verify(
          [_with(b1, signature: b1.signature.sublist(0, 64)), b2],
        ),
        isFalse,
      );
      expect(
        Ed256189BatchVerify.verify([
          _with(b1, signature: Uint8List.fromList([...b1.signature, 0])),
          b2,
        ]),
        isFalse,
      );
      expect(
        Ed256189BatchVerify.verify(
          [_with(b1, publicKey: b1.publicKey.sublist(0, 32)), b2],
        ),
        isFalse,
      );
    });

    test('low-order public key and low-order R', () {
      for (final point in [identity, order2, order4Even, order4Odd]) {
        final encoded = DualEdwards.encodePoint(point);
        expect(
          Ed256189BatchVerify.verify([_with(b1, publicKey: encoded), b2]),
          isFalse,
        );
        expect(
          Ed256189BatchVerify.verify([
            _with(b1, signature: withSignature(encoded, s)),
            b2,
          ]),
          isFalse,
        );
      }
    });

    test('mixed-order public key', () {
      final mixed = DualEdwards.add(gDual, order2);
      expect(
        Ed256189BatchVerify.verify([
          _with(b1, publicKey: DualEdwards.encodePoint(mixed)),
          b2,
        ]),
        isFalse,
      );
    });

    test('all-zero signature', () {
      expect(
        Ed256189BatchVerify.verify([_with(b1, signature: Uint8List(65)), b2]),
        isFalse,
      );
    });

    test('non-canonical point encodings', () {
      final badV = Uint8List.fromList([...encodeLE32(p), 0]);
      expect(
        Ed256189BatchVerify.verify([
          _with(b1, signature: withSignature(badV, s)),
          b2,
        ]),
        isFalse,
      );
      expect(
        Ed256189BatchVerify.verify([_with(b1, publicKey: badV), b2]),
        isFalse,
      );

      final badParity = Uint8List.fromList(b1.publicKey)..[32] = 2;
      expect(
        Ed256189BatchVerify.verify([_with(b1, publicKey: badParity), b2]),
        isFalse,
      );
    });

    test('random signatures and public keys never throw', () {
      final rng = Random(17);
      for (var i = 0; i < 25; i++) {
        final sig = Uint8List.fromList(
          List.generate(65, (_) => rng.nextInt(256)),
        );
        final pk = Uint8List.fromList(
          List.generate(33, (_) => rng.nextInt(256)),
        );
        final msg = Uint8List.fromList(
          List.generate(7, (_) => rng.nextInt(256)),
        );
        expect(
          () => Ed256189BatchVerify.verify([
            Ed256189SignatureBundle(
              message: msg,
              signature: sig,
              publicKey: pk,
            ),
            b2,
          ]),
          returnsNormally,
        );
      }
    });
  });

  group('batch and individual agree', () {
    final valid = [b1, b2, b3];
    final s1 = _decodeLE(b1.signature.sublist(33));

    final variants = <String, Ed256189SignatureBundle>{
      'valid': b1,
      'wrong message': _with(b1, message: bytesOf('Wrong message!')),
      'tampered signature': _with(
        b1,
        signature: Uint8List.fromList(b1.signature)..[7] ^= 0x04,
      ),
      'wrong public key': _with(b1, publicKey: b2.publicKey),
      'S >= n': _with(
        b1,
        signature: Uint8List.fromList([
          ...b1.signature.sublist(0, 33),
          ...encodeLE32(s1 + n),
        ]),
      ),
      'low-order public key': _with(
        b1,
        publicKey: DualEdwards.encodePoint(identity),
      ),
      'low-order R': _with(
        b1,
        signature: Uint8List.fromList([
          ...DualEdwards.encodePoint(order2),
          ...b1.signature.sublist(33),
        ]),
      ),
      'short signature': _with(b1, signature: b1.signature.sublist(0, 64)),
    };

    for (final entry in variants.entries) {
      for (var position = 0; position < valid.length; position++) {
        test('${entry.key} at position $position', () {
          final batch = List<Ed256189SignatureBundle>.from(valid);
          batch[position] = entry.value;

          final individual = batch.every(
            (b) => Ed256189.verify(b.message, b.signature, b.publicKey),
          );
          expect(
            Ed256189BatchVerify.verify(batch),
            individual,
            reason: '${entry.key} at position $position',
          );
        });
      }
    }
  });

  group('scale and stability', () {
    test('large batch of 20 signatures', () {
      final twenty = List.generate(20, (i) => _bundle(i * 3 + 1, 'Large $i'));

      expect(
        twenty.every(
          (b) => Ed256189.verify(b.message, b.signature, b.publicKey),
        ),
        isTrue,
      );
      expect(Ed256189BatchVerify.verify(twenty), isTrue);

      final bad = List<Ed256189SignatureBundle>.from(twenty);
      bad[13] = _with(bad[13], message: bytesOf('tampered'));
      expect(Ed256189BatchVerify.verify(bad), isFalse);
    });

    test('repeated randomized runs are stable', () {
      for (var i = 0; i < 5; i++) {
        expect(Ed256189BatchVerify.verify([b1, b2, b3]), isTrue,
            reason: 'run=$i');
      }

      final tampered = _with(
        b1,
        signature: Uint8List.fromList(b1.signature)..[0] ^= 0x01,
      );
      for (var i = 0; i < 5; i++) {
        expect(Ed256189BatchVerify.verify([tampered, b2, b3]), isFalse,
            reason: 'run=$i');
      }
    });
  });
}
