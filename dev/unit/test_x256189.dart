// test_x256189.dart

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

int _passed = 0;
int _failed = 0;

void _check(String name, bool result) {
  print('  ${result ? "PASS" : "FAIL"}: $name');
  if (result) {
    _passed++;
  } else {
    _failed++;
  }
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List _encodeX(BigInt x) {
  final out = Uint8List(32);
  var v = x;
  for (int i = 0; i < 32; i++) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v = v >> 8;
  }
  return out;
}

void main() {
  print('=== Test: X256189 ECDH + XEdDSA Curve256189 ===');
  print('');

  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob = Uint8List.fromList(List.generate(32, (i) => i + 33));

  print('Test 1 - Key generation:');
  final aliceKP = X256189.generateKeyPair(seedAlice);
  final bobKP = X256189.generateKeyPair(seedBob);
  print('  Alice PK: ${_hex(aliceKP['publicKey']!)}');
  print('  Bob PK:   ${_hex(bobKP['publicKey']!)}');
  _check('public key is 32 bytes', aliceKP['publicKey']!.length == 32);
  _check('private key is the seed',
      _hex(aliceKP['privateKey']!) == _hex(seedAlice));

  print('');
  print('Test 2 - Shared secret agreement:');
  final sharedAlice = X256189.computeSharedSecret(
    aliceKP['privateKey']!,
    bobKP['publicKey']!,
  );
  final sharedBob = X256189.computeSharedSecret(
    bobKP['privateKey']!,
    aliceKP['publicKey']!,
  );
  _check(
      'both sides derive a secret', sharedAlice != null && sharedBob != null);
  _check(
      'shared secrets match',
      sharedAlice != null &&
          sharedBob != null &&
          _hex(sharedAlice) == _hex(sharedBob));

  print('');
  print('Test 3 - Invalid public keys:');
  _check(
    'zero public key rejected',
    X256189.computeSharedSecret(aliceKP['privateKey']!, Uint8List(32)) == null,
  );
  _check(
    'x = p - 1 (order 4) rejected',
    X256189.computeSharedSecret(
          aliceKP['privateKey']!,
          _encodeX(Curve256189Params.p - BigInt.one),
        ) ==
        null,
  );
  final mixed = Montgomery.add(
    MontgomeryPoint.G,
    MontgomeryPoint(BigInt.zero, BigInt.zero),
  );
  _check(
    'mixed-order public key rejected',
    X256189.computeSharedSecret(aliceKP['privateKey']!, _encodeX(mixed.x)) ==
        null,
  );
  _check(
    '31-byte public key rejected',
    X256189.computeSharedSecret(
          aliceKP['privateKey']!,
          aliceKP['publicKey']!.sublist(0, 31),
        ) ==
        null,
  );

  print('');
  print('Test 4 - XEdDSA uses the same public key:');
  final aliceEdKP = XEdDSA.generateKeyPair(seedAlice);
  _check(
    'XEdDSA and X256189 public keys match',
    _hex(aliceEdKP['publicKey']!) == _hex(aliceKP['publicKey']!),
  );

  print('');
  print('Test 5 - Sign and verify:');
  final message = Uint8List.fromList('Hello X256189!'.codeUnits);
  final signature = XEdDSA.sign(message, aliceEdKP['privateKey']!);
  _check('valid signature verifies',
      XEdDSA.verify(message, signature, aliceEdKP['publicKey']!));
  _check(
    'tampered message fails',
    !XEdDSA.verify(
      Uint8List.fromList('Hello X256189?'.codeUnits),
      signature,
      aliceEdKP['publicKey']!,
    ),
  );

  print('');
  print('Test 6 - Combined ECDH + signature:');
  final combinedMessage = Uint8List.fromList([...sharedAlice!, ...message]);
  final combinedSig = XEdDSA.sign(combinedMessage, aliceEdKP['privateKey']!);
  _check('combined message verifies',
      XEdDSA.verify(combinedMessage, combinedSig, aliceEdKP['publicKey']!));

  print('');
  print('=== Results: $_passed passed, $_failed failed ===');
}
