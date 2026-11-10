/// XEdDSA signatures on Curve256189.
///
/// XEdDSA is a supported alternative to Ed256189 when one x-only key must serve
/// both X256189 ECDH and signatures (see eddsa_example.dart for Ed256189). Its
/// 32-byte public key is the same key as the X256189 ECDH public key.
///
/// XEdDSA is an x-only Schnorr-style scheme built on the Montgomery form:
///
/// * 32-byte x-only public keys, shared with X256189;
/// * 64-byte signatures, x(R) || s;
/// * deterministic signatures, so the same message and key always produce
///   the same signature;
/// * strict verification that rejects non-canonical and malleated values.
library;

import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';

void main() {
  print('');
  print('Curve256189 XEdDSA signatures (x-only, shared with X256189)');
  print('=' * 55);
  print('');

  _step('1. Generate a key pair');

  final seed = _demoSeed(0x01);
  final keyPair = XEdDSA.generateKeyPair(seed);
  final privateKey = keyPair['privateKey']!;
  final publicKey = keyPair['publicKey']!;

  print('Private key (seed): ${_hex(privateKey)}');
  print('Public key (${publicKey.length} bytes): ${_hex(publicKey)}');

  final x256189 = X256189.generateKeyPair(seed);
  print('Matches X256189 public key: '
      '${_bytesEqual(publicKey, x256189['publicKey']!)}');
  print('');

  _step('2. Sign a message');

  final message = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  final signature = XEdDSA.sign(message, privateKey);

  print('Message:   "${String.fromCharCodes(message)}"');
  print('Signature (${signature.length} bytes): ${_hex(signature)}');
  print('');

  _step('3. Verify the signature');

  final valid = XEdDSA.verify(message, signature, publicKey);
  print('Signature valid: $valid');
  print('');

  _step('4. Invalid inputs are rejected');

  final wrongMessage = Uint8List.fromList('Wrong message'.codeUnits);
  print('Wrong message:       '
      '${XEdDSA.verify(wrongMessage, signature, publicKey)}');

  final tamperedSignature = Uint8List.fromList(signature);
  tamperedSignature[0] ^= 0x01;
  print('Tampered signature:  '
      '${XEdDSA.verify(message, tamperedSignature, publicKey)}');

  final otherKey = XEdDSA.generateKeyPair(_demoSeed(0x41));
  print('Wrong public key:    '
      '${XEdDSA.verify(message, signature, otherKey['publicKey']!)}');

  // s is canonical, so n - s must not be accepted as a second signature.
  final n = Curve256189Params.n;
  final xR = signature.sublist(0, 32);
  final s = XEdDSA.decodeLittleEndian(signature.sublist(32));
  final malleated = Uint8List.fromList([
    ...xR,
    ...XEdDSA.encodeScalar((n - s) % n),
  ]);
  print('Malleated (n - s):   '
      '${XEdDSA.verify(message, malleated, publicKey)}');
  print('');

  _step('5. Signatures are deterministic');

  final second = XEdDSA.sign(message, privateKey);
  print('Second signature equals the first: ${_bytesEqual(signature, second)}');
  print('');

  print('XEdDSA is supported. Use Ed256189 for signature-only designs;');
  print('use XEdDSA when one x-only key must serve ECDH and signatures.');
  print('');
}

void _step(String title) {
  print(title);
  print('-' * title.length);
}

Uint8List _demoSeed(int start) => Uint8List.fromList(
      List<int>.generate(32, (i) => (start + i) & 0xff),
    );

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
