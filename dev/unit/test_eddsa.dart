// test_eddsa.dart

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: EdDSA Curve256189 ===');
  print('');

  // Test 1: Key Generation
  // Note: EdDSA output is DETERMINISTIC
  // Same seed always produces same public key and signature
  // Scalar blinding only affects internal computation, not output
  print('Test 1 - Key Generation:');
  final seed = Uint8List.fromList([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  ]);
  final keyPair = EdDSA.generateKeyPair(seed);
  final privateKey = keyPair['privateKey']!;
  final publicKey = keyPair['publicKey']!;
  print('  Private Key (seed): ${privateKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Public Key: ${publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Public Key length: ${publicKey.length} bytes');
  print('');

  // Test case 2: Sign a message
  print('Test 2 - Sign:');
  final message = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  final signature = EdDSA.sign(message, privateKey);
  print('  Message: "Hello Curve256189!"');
  print('  Signature: ${signature.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Signature length: ${signature.length} bytes');
  print('');

  // Test case 3: Verify that signature length is 65 bytes
  print('Test 3 - Is signature length == 65 bytes?');
  print('  Valid? ${signature.length == 65}');
  print('');

  // Test case 4: Different messages produce different signatures
  print('Test 4 - Do different messages produce different signatures?');
  final message2 = Uint8List.fromList('Hello World!'.codeUnits);
  final signature2 = EdDSA.sign(message2, privateKey);
  print('  Signature 1: ${signature.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  Signature 2: ${signature2.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  Different? ${signature.join() != signature2.join()}');
  print('');

  // Test case 5: Different seeds produce different public keys
  print('Test 5 - Do different seeds produce different public keys?');
  final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 2));
  final keyPair2 = EdDSA.generateKeyPair(seed2);
  final publicKey2 = keyPair2['publicKey']!;
  print('  PK 1: ${publicKey.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  PK 2: ${publicKey2.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  Different? ${publicKey.join() != publicKey2.join()}');
  print('');

  // Test case 6: Verify a valid signature
  print('Test 6 - Verify a valid signature:');
  final isValid = EdDSA.verify(message, signature, publicKey);
  print('  Valid? $isValid');
  print('');

  // Test case 7: Verify with a tampered message
  print('Test 7 - Verify with a tampered message:');
  final fakeMessage = Uint8List.fromList('Hello Curve256189? FAKE!'.codeUnits);
  final isValidFake = EdDSA.verify(fakeMessage, signature, publicKey);
  print('  Valid? $isValidFake');
  print('');

  // Test case 8: Verify with the wrong public key
  print('Test 8 - Verify with the wrong public key:');
  final isValidFakePK = EdDSA.verify(message, signature, publicKey2);
  print('  Valid? $isValidFakePK');
  print('');

  // Test case 9: Verify with a tampered signature
  print('Test 9 - Verify with a tampered signature:');
  final fakeSignature = Uint8List.fromList(signature);
  fakeSignature[0] ^= 0x01;  // Flip one bit
  final isValidFakeSig = EdDSA.verify(message, fakeSignature, publicKey);
  print('  Valid? $isValidFakeSig');
  print('');

  print('=== All Tests Completed ===');
}