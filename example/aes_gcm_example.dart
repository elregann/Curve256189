/// AES-256-GCM authenticated encryption.
///
/// GCM provides confidentiality, integrity and authenticity in one operation.
/// This example uses a fixed key and nonce so the output is reproducible.
/// In real code, derive the key with HKDF and never reuse a (key, nonce) pair.
library;

import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';

void main() {
  print('');
  print('Curve256189 AES-256-GCM authenticated encryption');
  print('=' * 47);
  print('');

  _step('1. Key and nonce');

  final key = _demoKey();
  final nonce = _demoNonce();

  print('Key (${key.length} bytes, AES-256): ${_hex(key)}');
  print('Nonce (${nonce.length} bytes, GCM):  ${_hex(nonce)}');
  print('');

  _step('2. Encrypt');

  final plaintext = Uint8List.fromList('This is a secret message!'.codeUnits);
  final sealed = AESGCM.encrypt(key: key, nonce: nonce, plaintext: plaintext);

  print('Plaintext:  "${String.fromCharCodes(plaintext)}"');
  print('Ciphertext: ${_hex(sealed.ciphertext)}');
  print('Tag:        ${_hex(sealed.tag)}');
  print('Ciphertext length equals plaintext length: '
      '${sealed.ciphertext.length == plaintext.length}');
  print('');

  _step('3. Decrypt');

  final opened = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: sealed.ciphertext,
    tag: sealed.tag,
  );

  if (opened == null) {
    print('ERROR: decryption failed.');
    return;
  }

  print('Plaintext:  "${String.fromCharCodes(opened)}"');
  print('Matches original: ${_bytesEqual(opened, plaintext)}');
  print('');

  _step('4. Tampering is rejected');

  final tamperedCiphertext = Uint8List.fromList(sealed.ciphertext);
  tamperedCiphertext[0] ^= 0x01;
  final ciphertextResult = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: tamperedCiphertext,
    tag: sealed.tag,
  );
  print(
      'Tampered ciphertext: ${ciphertextResult == null ? 'REJECTED' : 'ACCEPTED'}');

  final tamperedTag = Uint8List.fromList(sealed.tag);
  tamperedTag[0] ^= 0x01;
  final tagResult = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: sealed.ciphertext,
    tag: tamperedTag,
  );
  print('Tampered tag:        ${tagResult == null ? 'REJECTED' : 'ACCEPTED'}');

  final wrongKey = _demoKey(offset: 100);
  final wrongKeyResult = AESGCM.decrypt(
    key: wrongKey,
    nonce: nonce,
    ciphertext: sealed.ciphertext,
    tag: sealed.tag,
  );
  print(
      'Wrong key:           ${wrongKeyResult == null ? 'REJECTED' : 'ACCEPTED'}');
  print('');

  _step('5. Additional authenticated data (AAD)');

  // AAD is authenticated but not encrypted. It is useful for headers or
  // protocol metadata that must travel in the clear but must not change.
  final aad = Uint8List.fromList('version=1;type=message'.codeUnits);
  final withAad = AESGCM.encrypt(
    key: key,
    nonce: nonce,
    plaintext: plaintext,
    aad: aad,
  );

  final aadOk = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: withAad.ciphertext,
    tag: withAad.tag,
    aad: aad,
  );
  final aadWrong = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: withAad.ciphertext,
    tag: withAad.tag,
    aad: Uint8List.fromList('version=2;type=message'.codeUnits),
  );

  print('Correct AAD accepted: ${aadOk != null}');
  print('Wrong AAD rejected:   ${aadWrong == null}');
  print('');

  print('Never reuse a (key, nonce) pair with GCM: doing so breaks both');
  print('confidentiality and authenticity. Use a random 96-bit nonce or a');
  print('strictly increasing counter.');
  print('');
}

void _step(String title) {
  print(title);
  print('-' * title.length);
}

Uint8List _demoKey({int offset = 0}) => Uint8List.fromList(
      List<int>.generate(32, (i) => (offset + i) & 0xff),
    );

Uint8List _demoNonce() => Uint8List.fromList(
      List<int>.generate(12, (i) => (0xa0 + i) & 0xff),
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
