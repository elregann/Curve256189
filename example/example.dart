/// Complete workflow: X256189 ECDH -> HKDF-SHA256 -> AES-256-GCM.
///
/// This example shows the pattern behind most end-to-end encryption systems:
///
/// 1. Alice and Bob agree on a shared secret with X256189 (ECDH).
/// 2. Both sides derive the same AES-256 key with HKDF-SHA256.
/// 3. Each message is encrypted with a distinct GCM nonce.
/// 4. Bob decrypts, while an eavesdropper and a tamperer both fail.
///
/// The seeds and counter are fixed so the output is reproducible. In real
/// code, generate seeds with a cryptographically secure random number
/// generator and never reuse a (key, nonce) pair.
library;

import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';

const String _keyInfo = 'curve256189-aes-key';
const String _nonceInfo = 'curve256189-nonce';

void main() {
  print('');
  print('Curve256189 complete workflow: ECDH -> HKDF -> AES-256-GCM');
  print('=' * 60);
  print('');

  _step('1. Key exchange (X256189 ECDH)');

  final alice = X256189.generateKeyPair(_demoSeed(0x01));
  final bob = X256189.generateKeyPair(_demoSeed(0x21));

  final alicePrivate = alice['privateKey']!;
  final alicePublic = alice['publicKey']!;
  final bobPrivate = bob['privateKey']!;
  final bobPublic = bob['publicKey']!;

  print('Alice public key: ${_short(alicePublic)}');
  print('Bob   public key: ${_short(bobPublic)}');

  final aliceSecret = X256189.computeSharedSecret(alicePrivate, bobPublic);
  final bobSecret = X256189.computeSharedSecret(bobPrivate, alicePublic);

  if (aliceSecret == null || bobSecret == null) {
    print('ERROR: could not compute the shared secret.');
    return;
  }
  if (!_bytesEqual(aliceSecret, bobSecret)) {
    print('ERROR: Alice and Bob derived different shared secrets.');
    return;
  }

  print('Shared secret:    ${_short(aliceSecret)}');
  print('Both sides agree: true');
  print('');

  _step('2. Key derivation (HKDF-SHA256)');

  final aesKey = HKDF.derive(
    ikm: aliceSecret,
    info: Uint8List.fromList(_keyInfo.codeUnits),
    length: 32,
  );
  print('AES-256 key: ${_short(aesKey)}');
  print('');

  // A fresh nonce per message. Binding the counter into the HKDF info keeps
  // the nonce deterministic here while remaining unique for each message.
  Uint8List nonceFor(int counter) => HKDF.derive(
        ikm: aliceSecret,
        info: Uint8List.fromList([
          ..._nonceInfo.codeUnits,
          counter & 0xff,
          (counter >> 8) & 0xff,
          (counter >> 16) & 0xff,
          (counter >> 24) & 0xff,
        ]),
        length: 12,
      );

  _step('3. Encrypt two messages with distinct nonces');

  final message1 = Uint8List.fromList('Attack at dawn.'.codeUnits);
  final message2 = Uint8List.fromList('Retreat at dusk.'.codeUnits);

  final nonce1 = nonceFor(0);
  final nonce2 = nonceFor(1);

  final sealed1 =
      AESGCM.encrypt(key: aesKey, nonce: nonce1, plaintext: message1);
  final sealed2 =
      AESGCM.encrypt(key: aesKey, nonce: nonce2, plaintext: message2);

  print('Message 1: "${String.fromCharCodes(message1)}"');
  print('  nonce:      ${_short(nonce1)}');
  print('  ciphertext: ${_short(sealed1.ciphertext)}');
  print('  tag:        ${_short(sealed1.tag)}');
  print('');
  print('Message 2: "${String.fromCharCodes(message2)}"');
  print('  nonce:      ${_short(nonce2)}');
  print('  ciphertext: ${_short(sealed2.ciphertext)}');
  print('  tag:        ${_short(sealed2.tag)}');
  print('');

  _step('4. Bob decrypts');

  final bobKey = HKDF.derive(
    ikm: bobSecret,
    info: Uint8List.fromList(_keyInfo.codeUnits),
    length: 32,
  );

  final opened1 = AESGCM.decrypt(
    key: bobKey,
    nonce: nonce1,
    ciphertext: sealed1.ciphertext,
    tag: sealed1.tag,
  );
  final opened2 = AESGCM.decrypt(
    key: bobKey,
    nonce: nonce2,
    ciphertext: sealed2.ciphertext,
    tag: sealed2.tag,
  );

  if (opened1 == null || opened2 == null) {
    print('ERROR: Bob could not decrypt a message.');
    return;
  }

  print('Message 1: "${String.fromCharCodes(opened1)}"');
  print('  matches plaintext: ${_bytesEqual(opened1, message1)}');
  print('Message 2: "${String.fromCharCodes(opened2)}"');
  print('  matches plaintext: ${_bytesEqual(opened2, message2)}');
  print('');

  _step('5. Negative cases');

  // Eve has her own key pair but not Alice's or Bob's private key.
  final eve = X256189.generateKeyPair(_demoSeed(0x41));
  final eveSecret = X256189.computeSharedSecret(eve['privateKey']!, bobPublic);
  if (eveSecret != null) {
    final eveKey = HKDF.derive(
      ikm: eveSecret,
      info: Uint8List.fromList(_keyInfo.codeUnits),
      length: 32,
    );
    final eveAttempt = AESGCM.decrypt(
      key: eveKey,
      nonce: nonce1,
      ciphertext: sealed1.ciphertext,
      tag: sealed1.tag,
    );
    print('Eavesdropper with her own key pair: '
        '${eveAttempt == null ? 'REJECTED' : 'ACCEPTED'}');
  }

  final tamperedCiphertext = Uint8List.fromList(sealed1.ciphertext);
  tamperedCiphertext[0] ^= 0x01;
  final tamperedCiphertextResult = AESGCM.decrypt(
    key: bobKey,
    nonce: nonce1,
    ciphertext: tamperedCiphertext,
    tag: sealed1.tag,
  );
  print('Tampered ciphertext:                '
      '${tamperedCiphertextResult == null ? 'REJECTED' : 'ACCEPTED'}');

  final tamperedTag = Uint8List.fromList(sealed1.tag);
  tamperedTag[0] ^= 0x01;
  final tamperedTagResult = AESGCM.decrypt(
    key: bobKey,
    nonce: nonce1,
    ciphertext: sealed1.ciphertext,
    tag: tamperedTag,
  );
  print('Tampered authentication tag:        '
      '${tamperedTagResult == null ? 'REJECTED' : 'ACCEPTED'}');
  print('');

  print('Never reuse a (key, nonce) pair. This example derives a fresh');
  print('nonce from a per-message counter; a random 96-bit nonce or a');
  print('strictly increasing counter works as well.');
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

String _short(Uint8List bytes) {
  final hex = _hex(bytes);
  return hex.length > 32 ? '${hex.substring(0, 32)}...' : hex;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
