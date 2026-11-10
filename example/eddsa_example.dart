/// Ed256189 signatures: RFC 8032-shaped EdDSA on Curve256189.
///
/// Ed256189 is the current signature scheme. It lives on the complete dual
/// twisted Edwards curve E_{d,a}, so the addition law has no exceptional
/// inputs. Keys and signatures are:
///
/// * private key: a 32-byte seed;
/// * public key: 33 bytes, the encoded Edwards point;
/// * signature: 65 bytes, R (33 bytes) || S (32 bytes).
///
/// Keys are independent from X256189 and XEdDSA keys derived from the same
/// seed. The seed below is fixed so the output is reproducible; in real code,
/// generate it with a cryptographically secure random number generator.
library;

import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';

void main() {
  print('');
  print('Curve256189 Ed256189 signatures');
  print('=' * 31);
  print('');

  _step('1. Generate a key pair');

  final seed = _demoSeed(0x01);
  final keyPair = Ed256189.generateKeyPair(seed);
  final privateKey = keyPair['privateKey']!;
  final publicKey = keyPair['publicKey']!;

  print('Private key (${privateKey.length}-byte seed): ${_hex(privateKey)}');
  print('Public key (${publicKey.length} bytes): ${_hex(publicKey)}');
  print('Public key from seed matches: '
      '${_bytesEqual(publicKey, Ed256189.publicKeyFromSeed(seed))}');

  final x256189 = X256189.generateKeyPair(seed);
  print('X256189 public key for the same seed (independent): '
      '${_hex(x256189['publicKey']!)}');
  print('');

  _step('2. Sign a message');

  // This message and seed match the published seed1/curve test vector, so the
  // public key and signature below can be checked against
  // test/ed256189_vectors.dart.
  final message = Uint8List.fromList('Curve256189 Ed256189'.codeUnits);
  final signature = Ed256189.sign(message, privateKey);

  print('Message:   "${String.fromCharCodes(message)}"');
  print('Signature (${signature.length} bytes): ${_hex(signature)}');
  print('  R (33 bytes): ${_hex(signature.sublist(0, 33))}');
  print('  S (32 bytes): ${_hex(signature.sublist(33))}');
  print('');

  _step('3. Verify the signature');

  final valid = Ed256189.verify(message, signature, publicKey);
  print('Signature valid: $valid');
  print('');

  _step('4. Invalid inputs are rejected');

  final wrongMessage = Uint8List.fromList('Wrong message'.codeUnits);
  print('Wrong message:        '
      '${Ed256189.verify(wrongMessage, signature, publicKey)}');

  final tamperedSignature = Uint8List.fromList(signature);
  tamperedSignature[0] ^= 0x01;
  print('Tampered signature:   '
      '${Ed256189.verify(message, tamperedSignature, publicKey)}');

  final otherKey = Ed256189.generateKeyPair(_demoSeed(0x41));
  print('Wrong public key:     '
      '${Ed256189.verify(message, signature, otherKey['publicKey']!)}');

  // Verification never throws on malformed input; it returns false.
  print('Truncated signature:  '
      '${Ed256189.verify(message, Uint8List(10), publicKey)}');
  print('');

  _step('5. Signatures are deterministic');

  final second = Ed256189.sign(message, privateKey);
  print('Second signature equals the first: ${_bytesEqual(signature, second)}');
  print('');

  print('Ed256189 is the recommended signature scheme for Curve256189.');
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
