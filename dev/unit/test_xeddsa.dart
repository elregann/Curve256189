// test_xeddsa.dart

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
  print('=== Test: XEdDSA Curve256189 ===');
  print('');

  final seed = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final keyPair = XEdDSA.generateKeyPair(seed);
  final privateKey = keyPair['privateKey']!;
  final publicKey = keyPair['publicKey']!;

  print('Test 1 - Key generation:');
  print('  Public Key: ${_hex(publicKey)}');
  _check('public key is 32 bytes', publicKey.length == 32);
  _check(
    'public key matches X256189 for the same seed',
    _hex(publicKey) == _hex(X256189.generateKeyPair(seed)['publicKey']!),
  );
  _check(
    'public key is a prime-order point',
    Montgomery.isValidPublicKeyX(XEdDSA.decodeLittleEndian(publicKey)),
  );

  print('');
  print('Test 2 - Deterministic signature:');
  final message = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  final signature = XEdDSA.sign(message, privateKey);
  final signatureAgain = XEdDSA.sign(message, privateKey);
  print('  Signature: ${_hex(signature)}');
  _check('signature is 64 bytes', signature.length == 64);
  _check('signature is deterministic', _hex(signature) == _hex(signatureAgain));
  _check(
    'signature matches the documented test vector',
    _hex(signature) ==
        'c87e2d535cab5c2ede5993907c4c8d97'
            'aa6be84dd9de5b0b4b39e56d4d084284'
            'ee7a80cfbff274f44f74b7a03b49b744'
            'c481f702a80c35a93ff03ad11cef142e',
  );

  print('');
  print('Test 3 - Signature verification:');
  _check(
      'valid signature verifies', XEdDSA.verify(message, signature, publicKey));
  _check(
    'tampered message is rejected',
    !XEdDSA.verify(
      Uint8List.fromList('Hello Curve256189?'.codeUnits),
      signature,
      publicKey,
    ),
  );
  final otherKeyPair = XEdDSA.generateKeyPair(
      Uint8List.fromList(List.generate(32, (i) => i + 2)));
  _check(
    'wrong public key is rejected',
    !XEdDSA.verify(message, signature, otherKeyPair['publicKey']!),
  );

  final tampered = Uint8List.fromList(signature);
  tampered[0] ^= 0x01;
  _check(
      'tampered R is rejected', !XEdDSA.verify(message, tampered, publicKey));

  final tamperedS = Uint8List.fromList(signature);
  tamperedS[40] ^= 0x01;
  _check(
      'tampered s is rejected', !XEdDSA.verify(message, tamperedS, publicKey));

  print('');
  print('Test 4 - Signature malleability:');
  final n = Curve256189Params.n;
  final s =
      XEdDSA.decodeLittleEndian(Uint8List.fromList(signature.sublist(32)));
  final xR = Uint8List.fromList(signature.sublist(0, 32));

  final nMinusS =
      Uint8List.fromList([...xR, ...XEdDSA.encodeScalar((n - s) % n)]);
  _check(
      '(x(R), n - s) is rejected', !XEdDSA.verify(message, nMinusS, publicKey));

  var sPlusN = s + n;
  final sPlusNBytes = Uint8List(32);
  for (int i = 0; i < 32; i++) {
    sPlusNBytes[i] = (sPlusN & BigInt.from(0xff)).toInt();
    sPlusN >>= 8;
  }
  final nonCanonicalS = Uint8List.fromList([...xR, ...sPlusNBytes]);
  _check('(x(R), s + n) is rejected',
      !XEdDSA.verify(message, nonCanonicalS, publicKey));

  print('');
  print('Test 5 - Encoding length checks:');
  _check('short signature is rejected',
      !XEdDSA.verify(message, signature.sublist(0, 63), publicKey));
  _check(
      'long signature is rejected',
      !XEdDSA.verify(
          message, Uint8List.fromList([...signature, 0]), publicKey));
  _check('short public key is rejected',
      !XEdDSA.verify(message, signature, publicKey.sublist(0, 31)));
  _check(
      'long public key is rejected',
      !XEdDSA.verify(
          message, signature, Uint8List.fromList([...publicKey, 0])));

  print('');
  print('Test 6 - Invalid public keys:');
  final p = Curve256189Params.p;
  _check('x = 0 (order 2) is rejected',
      !XEdDSA.verify(message, signature, Uint8List(32)));
  _check('x = p - 1 (order 4) is rejected',
      !XEdDSA.verify(message, signature, _encodeX(p - BigInt.one)));

  final sBytes = signature.sublist(32);
  _check(
    'R = 0 (order 2) is rejected',
    !XEdDSA.verify(
      message,
      Uint8List.fromList([...Uint8List(32), ...sBytes]),
      publicKey,
    ),
  );
  _check(
    'R = p - 1 (order 4) is rejected',
    !XEdDSA.verify(
      message,
      Uint8List.fromList([..._encodeX(p - BigInt.one), ...sBytes]),
      publicKey,
    ),
  );
  _check(
    'all-zero signature is rejected',
    !XEdDSA.verify(message, Uint8List(64), publicKey),
  );

  final mixed = Montgomery.add(
    MontgomeryPoint.G,
    MontgomeryPoint(BigInt.zero, BigInt.zero),
  );
  _check('mixed-order public key is rejected',
      !XEdDSA.verify(message, signature, _encodeX(mixed.x)));

  print('');
  print('Test 7 - Seed validation:');
  var threw = false;
  try {
    XEdDSA.generateKeyPair(Uint8List(31));
  } on ArgumentError {
    threw = true;
  }
  _check('31-byte seed is rejected', threw);

  print('');
  print('=== Results: $_passed passed, $_failed failed ===');
}
