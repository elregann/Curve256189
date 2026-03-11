import 'dart:typed_data';
import 'eddsa.dart';

void main() {
  print('=== Test EdDSA Curve256189 ===\n');

  // Test 1: Key Generation
  print('Test 1 - Key Generation:');
  final seed = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final keyPair = EdDSA.generateKeyPair(seed);
  final privateKey = keyPair['privateKey']!;
  final publicKey = keyPair['publicKey']!;
  print('  Private Key (seed): ${privateKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Public Key: ${publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Public Key length: ${publicKey.length} bytes\n');

  // Test 2: Sign
  print('Test 2 - Sign:');
  final message = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  final signature = EdDSA.sign(message, privateKey);
  print('  Message: "Hello Curve256189!"');
  print('  Signature: ${signature.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Signature length: ${signature.length} bytes\n');

  // Test 3: Signature length valid?
  print('Test 3 - Signature length == 65 bytes?');
  print('  Valid? ${signature.length == 65}\n');

  // Test 4: Sign pesan berbeda menghasilkan signature berbeda?
  print('Test 4 - Pesan berbeda = Signature berbeda?');
  final message2 = Uint8List.fromList('Hello World!'.codeUnits);
  final signature2 = EdDSA.sign(message2, privateKey);
  print('  Signature 1: ${signature.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  Signature 2: ${signature2.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  Berbeda? ${signature.join() != signature2.join()}\n');

  // Test 5: Key berbeda = Public key berbeda?
  print('Test 5 - Seed berbeda = Public key berbeda?');
  final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 2));
  final keyPair2 = EdDSA.generateKeyPair(seed2);
  final publicKey2 = keyPair2['publicKey']!;
  print('  PK 1: ${publicKey.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  PK 2: ${publicKey2.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join()}...');
  print('  Berbeda? ${publicKey.join() != publicKey2.join()}\n');

  // Test 6: Verify signature valid?
  print('Test 6 - Verify signature yang valid:');
  final isValid = EdDSA.verify(message, signature, publicKey);
  print('  Valid? $isValid\n');

  // Test 7: Verify signature dengan pesan yang diubah?
  print('Test 7 - Verify signature dengan pesan diubah:');
  final fakeMessage = Uint8List.fromList('Hello Curve256189? FAKE!'.codeUnits);
  final isValidFake = EdDSA.verify(fakeMessage, signature, publicKey);
  print('  Valid? $isValidFake\n');

  // Test 8: Verify signature dengan public key yang salah?
  print('Test 8 - Verify signature dengan public key salah:');
  final isValidFakePK = EdDSA.verify(message, signature, publicKey2);
  print('  Valid? $isValidFakePK\n');

  // Test 9: Verify signature yang dimodifikasi?
  print('Test 9 - Verify signature yang dimodifikasi:');
  final fakeSignature = Uint8List.fromList(signature);
  fakeSignature[0] ^= 0x01; // flip 1 bit
  final isValidFakeSig = EdDSA.verify(message, fakeSignature, publicKey);
  print('  Valid? $isValidFakeSig\n');

  print('=== Semua Test Selesai ===');
}