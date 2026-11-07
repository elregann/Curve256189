import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  group('RFC 5869 test vectors (SHA-256)', () {
    test('test case 1', () {
      final ikm = Uint8List.fromList(List.filled(22, 0x0b));
      final salt = fromHex('000102030405060708090a0b0c');
      final info = fromHex('f0f1f2f3f4f5f6f7f8f9');
      final prk = HKDF.extract(salt, ikm);
      expect(toHex(prk),
          '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
      final okm = HKDF.expand(prk, info, 42);
      expect(
        toHex(okm),
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );
      expect(HKDF.derive(ikm: ikm, salt: salt, info: info, length: 42), okm);
    });

    test('test case 3 (empty salt and info)', () {
      final ikm = Uint8List.fromList(List.filled(22, 0x0b));
      final prk = HKDF.extract(Uint8List(0), ikm);
      expect(toHex(prk),
          '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04');
      final okm = HKDF.expand(prk, Uint8List(0), 42);
      expect(
        toHex(okm),
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'
        '9d201395faa4b61a96c8',
      );
    });
  });

  group('derive', () {
    final shared = fromHex(
        'a5ba314a475956d6a02d227c8ae094e673bf59eff0257e76f7d47c9e11ee6d3a');
    final info = bytesOf('X256189 shared key');

    test('published X256189 + HKDF vector (default salt)', () {
      expect(toHex(HKDF.derive(ikm: shared, info: info)),
          '55c8e6fdcbb611ef67fb69b6245f688a372828f56b78b5f6006d389ee215f6ba');
    });

    test('default salt is "Curve256189"', () {
      expect(
        HKDF.derive(ikm: shared, info: info),
        HKDF.derive(ikm: shared, salt: bytesOf('Curve256189'), info: info),
      );
      expect(
        HKDF.derive(ikm: shared, info: info),
        isNot(HKDF.derive(ikm: shared, salt: bytesOf('other'), info: info)),
      );
    });

    test('default length is 32 bytes; other lengths work', () {
      expect(HKDF.derive(ikm: shared, info: info).length, 32);
      for (final len in [1, 12, 31, 32, 33, 64, 100]) {
        expect(HKDF.derive(ikm: shared, info: info, length: len).length, len);
      }
    });

    test('shorter outputs are prefixes of longer ones', () {
      final long = HKDF.derive(ikm: shared, info: info, length: 80);
      expect(HKDF.derive(ikm: shared, info: info, length: 20), long.sublist(0, 20));
      expect(HKDF.derive(ikm: shared, info: info, length: 64), long.sublist(0, 64));
    });

    test('ikm and info separate outputs', () {
      final base = HKDF.derive(ikm: shared, info: info);
      expect(HKDF.derive(ikm: Uint8List(32), info: info), isNot(base));
      expect(HKDF.derive(ikm: shared, info: bytesOf('X256189 auth key')),
          isNot(base));
    });

    test('ECDH + HKDF end to end', () {
      final a = X256189.generateKeyPair(seedFrom(1));
      final b = X256189.generateKeyPair(seedFrom(33));
      final ka = HKDF.derive(
          ikm: X256189.computeSharedSecret(a['privateKey']!, b['publicKey']!)!,
          info: info);
      final kb = HKDF.derive(
          ikm: X256189.computeSharedSecret(b['privateKey']!, a['publicKey']!)!,
          info: info);
      expect(ka, kb);
    });
  });
}
