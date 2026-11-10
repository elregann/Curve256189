/// X256189 ECDH key exchange between Alice and Bob.
///
/// ECDH lets two parties agree on a shared secret over a public channel.
/// The shared secret is not used directly as a key: pass it through a KDF
/// such as HKDF before encrypting anything (see example.dart).
///
/// X256189 keys are x-only: a private key is a 32-byte seed and a public key
/// is the 32-byte x-coordinate of the derived point.
library;

import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';

void main() {
  print('');
  print('Curve256189 ECDH key exchange (X256189)');
  print('=' * 40);
  print('');

  _step('1. Alice generates a key pair');

  final alice = X256189.generateKeyPair(_demoSeed(0x01));
  final alicePrivate = alice['privateKey']!;
  final alicePublic = alice['publicKey']!;

  print('Private key (seed, keep secret): ${_short(alicePrivate)}');
  print(
      'Public key (${alicePublic.length} bytes):          ${_hex(alicePublic)}');
  print('');

  _step('2. Bob generates a key pair');

  final bob = X256189.generateKeyPair(_demoSeed(0x21));
  final bobPrivate = bob['privateKey']!;
  final bobPublic = bob['publicKey']!;

  print('Private key (seed, keep secret): ${_short(bobPrivate)}');
  print('Public key (${bobPublic.length} bytes):          ${_hex(bobPublic)}');
  print('');

  _step('3. Both sides compute the shared secret');

  final aliceSecret = X256189.computeSharedSecret(alicePrivate, bobPublic);
  final bobSecret = X256189.computeSharedSecret(bobPrivate, alicePublic);

  if (aliceSecret == null || bobSecret == null) {
    print('ERROR: could not compute the shared secret.');
    return;
  }

  print('Alice computes: ${_hex(aliceSecret)}');
  print('Bob computes:   ${_hex(bobSecret)}');
  print('Secrets match:  ${_bytesEqual(aliceSecret, bobSecret)}');
  print('');

  _step('4. Invalid public keys are rejected');

  // An all-zero x-coordinate is not a valid Curve256189 public key.
  final invalid = X256189.computeSharedSecret(alicePrivate, Uint8List(32));
  print('All-zero public key accepted: ${invalid != null}');

  // Low-order and mixed-order points are rejected as well, so a malicious
  // peer cannot force the shared secret into a small subgroup.
  print('Low-order points are rejected by computeSharedSecret().');
  print('');

  _step('5. An eavesdropper cannot recover the secret');

  final eve = X256189.generateKeyPair(_demoSeed(0x41));
  final eveSecret = X256189.computeSharedSecret(eve['privateKey']!, bobPublic);

  if (eveSecret != null) {
    print('Eve computes:  ${_hex(eveSecret)}');
    print('Matches Alice: ${_bytesEqual(eveSecret, aliceSecret)}');
  }
  print('');

  print('ECDH example completed.');
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

String _short(Uint8List bytes) {
  final hex = _hex(bytes);
  return hex.length > 16 ? '${hex.substring(0, 16)}...' : hex;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
