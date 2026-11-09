import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  group('NIST / GCM spec test vectors (AES-256)', () {
    final zeroKey = Uint8List(32);
    final zeroNonce = Uint8List(12);

    test('test case 13: empty plaintext', () {
      final r = AESGCM.encrypt(
          key: zeroKey, nonce: zeroNonce, plaintext: Uint8List(0));
      expect(r.ciphertext, isEmpty);
      expect(toHex(r.tag), '530f8afbc74536b9a963b4f1c4cb738b');
    });

    test('test case 14: one zero block', () {
      final r = AESGCM.encrypt(
          key: zeroKey, nonce: zeroNonce, plaintext: Uint8List(16));
      expect(toHex(r.ciphertext), 'cea7403d4d606b6e074ec5d3baf39d18');
      expect(toHex(r.tag), 'd0d1c8a799996bf0265b98b5d48ab919');
    });

    test('test case 16: with AAD and a partial last block', () {
      final key = fromHex(
          'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
      final nonce = fromHex('cafebabefacedbaddecaf888');
      final plaintext = fromHex(
          'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
      final aad = fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
      final r = AESGCM.encrypt(
          key: key, nonce: nonce, plaintext: plaintext, aad: aad);
      expect(
        toHex(r.ciphertext),
        '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
        '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
      );
      expect(toHex(r.tag), '76fc6ece0f4e1768cddf8853bb2d551b');
      final back = AESGCM.decrypt(
          key: key,
          nonce: nonce,
          ciphertext: r.ciphertext,
          tag: r.tag,
          aad: aad);
      expect(back, plaintext);
    });
  });

  group('round trip and authentication', () {
    final key = Uint8List.fromList(List.generate(32, (i) => i));
    final nonce = Uint8List.fromList(List.generate(12, (i) => i));
    final plaintext = bytesOf('Hello Curve256189!');
    final aad = bytesOf('Curve256189 AAD');
    final sealed = AESGCM.encrypt(key: key, nonce: nonce, plaintext: plaintext);
    final sealedAad =
        AESGCM.encrypt(key: key, nonce: nonce, plaintext: plaintext, aad: aad);

    test('known ciphertext and tag (cross-checked with an independent AES-GCM)',
        () {
      expect(toHex(sealed.ciphertext), '0f67ba77aac5816eff37f2b984df4955baf7');
      expect(toHex(sealed.tag), '4ee590f9fa0611f994c0aff3531a78d5');
      expect(
          toHex(sealedAad.ciphertext), '0f67ba77aac5816eff37f2b984df4955baf7');
      expect(toHex(sealedAad.tag), '1f3eed002e4338797784809e67585ebe');
    });

    test('decrypts to the original plaintext', () {
      expect(
        AESGCM.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag),
        plaintext,
      );
    });

    test('ciphertext length equals plaintext length, tag is 16 bytes', () {
      expect(sealed.ciphertext.length, plaintext.length);
      expect(sealed.tag.length, 16);
    });

    test('lengths around the block size', () {
      for (final len in [0, 1, 15, 16, 17, 31, 32, 33, 100]) {
        final pt = Uint8List.fromList(List.generate(len, (i) => i * 7));
        final r = AESGCM.encrypt(key: key, nonce: nonce, plaintext: pt);
        expect(r.ciphertext.length, len);
        expect(
          AESGCM.decrypt(
              key: key, nonce: nonce, ciphertext: r.ciphertext, tag: r.tag),
          pt,
          reason: 'len=$len',
        );
      }
    });

    test('tampered ciphertext is rejected', () {
      final bad = Uint8List.fromList(sealed.ciphertext)..[0] ^= 0x01;
      expect(
          AESGCM.decrypt(
              key: key, nonce: nonce, ciphertext: bad, tag: sealed.tag),
          isNull);
    });

    test('tampered tag is rejected', () {
      final bad = Uint8List.fromList(sealed.tag)..[15] ^= 0x80;
      expect(
          AESGCM.decrypt(
              key: key, nonce: nonce, ciphertext: sealed.ciphertext, tag: bad),
          isNull);
    });

    test('truncated ciphertext is rejected', () {
      expect(
          AESGCM.decrypt(
              key: key,
              nonce: nonce,
              ciphertext: sealed.ciphertext.sublist(1),
              tag: sealed.tag),
          isNull);
    });

    test('wrong key and wrong nonce are rejected', () {
      final badKey = Uint8List.fromList(key)..[0] ^= 0x01;
      final badNonce = Uint8List.fromList(nonce)..[0] ^= 0x01;
      expect(
          AESGCM.decrypt(
              key: badKey,
              nonce: nonce,
              ciphertext: sealed.ciphertext,
              tag: sealed.tag),
          isNull);
      expect(
          AESGCM.decrypt(
              key: key,
              nonce: badNonce,
              ciphertext: sealed.ciphertext,
              tag: sealed.tag),
          isNull);
    });

    test('AAD must match', () {
      expect(
        AESGCM.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: sealedAad.ciphertext,
            tag: sealedAad.tag,
            aad: aad),
        plaintext,
      );
      expect(
        AESGCM.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: sealedAad.ciphertext,
            tag: sealedAad.tag,
            aad: bytesOf('Wrong AAD')),
        isNull,
      );
      expect(
        AESGCM.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: sealedAad.ciphertext,
            tag: sealedAad.tag),
        isNull,
      );
    });
  });

  group('input validation', () {
    final key = Uint8List(32);
    final nonce = Uint8List(12);
    final plaintext = bytesOf('validation');

    test('rejects wrong key length', () {
      expect(
        () => AESGCM.encrypt(
            key: Uint8List(31), nonce: nonce, plaintext: plaintext),
        throwsArgumentError,
      );
      expect(
        () => AESGCM.decrypt(
            key: Uint8List(33),
            nonce: nonce,
            ciphertext: Uint8List(0),
            tag: Uint8List(16)),
        throwsArgumentError,
      );
    });

    test('rejects wrong nonce length', () {
      expect(
        () => AESGCM.encrypt(
            key: key, nonce: Uint8List(11), plaintext: plaintext),
        throwsArgumentError,
      );
      expect(
        () => AESGCM.decrypt(
            key: key,
            nonce: Uint8List(13),
            ciphertext: Uint8List(0),
            tag: Uint8List(16)),
        throwsArgumentError,
      );
    });

    test('rejects wrong tag length', () {
      expect(
        () => AESGCM.decrypt(
            key: key,
            nonce: nonce,
            ciphertext: Uint8List(0),
            tag: Uint8List(15)),
        throwsArgumentError,
      );
    });
  });

  test('ECDH + HKDF + AES-GCM end to end', () {
    final alice = X256189.generateKeyPair(seedFrom(1));
    final bob = X256189.generateKeyPair(seedFrom(33));
    final sharedA =
        X256189.computeSharedSecret(alice['privateKey']!, bob['publicKey']!)!;
    final sharedB =
        X256189.computeSharedSecret(bob['privateKey']!, alice['publicKey']!)!;

    Uint8List keyFor(Uint8List s) =>
        HKDF.derive(ikm: s, info: bytesOf('Curve256189 AES key'));
    Uint8List nonceFor(Uint8List s) =>
        HKDF.derive(ikm: s, info: bytesOf('Curve256189 AES nonce'), length: 12);

    final message = bytesOf('Hello Bob! from Curve256189');
    final sealed = AESGCM.encrypt(
        key: keyFor(sharedA), nonce: nonceFor(sharedA), plaintext: message);
    final opened = AESGCM.decrypt(
        key: keyFor(sharedB),
        nonce: nonceFor(sharedB),
        ciphertext: sealed.ciphertext,
        tag: sealed.tag);
    expect(opened, message);
  });
}
