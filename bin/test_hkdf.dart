// test_hkdf.dart
import 'dart:typed_data';
import 'src/hkdf.dart';
import 'src/x256189.dart';

void main() {
  print('=== Test HKDF Curve256189 ===');

  // Shared secret dari test_x256189.dart
  final sharedSecret = Uint8List.fromList([
    0xa5, 0xba, 0x31, 0x4a, 0x47, 0x59, 0x56, 0xd6,
    0xa0, 0x2d, 0x22, 0x7c, 0x8a, 0xe0, 0x94, 0xe6,
    0x73, 0xbf, 0x59, 0xef, 0xf0, 0x25, 0x7e, 0x76,
    0xf7, 0xd4, 0x7c, 0x9e, 0x11, 0xee, 0x6d, 0x3a,
  ]);

  final info = Uint8List.fromList('X256189 shared key'.codeUnits);

  // Test 1: Derive key dari shared secret
  print('\nTest 1 - Derive key dari shared secret?');
  final derived = HKDF.derive(ikm: sharedSecret, info: info);
  print('  shared:  ${sharedSecret.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  derived: ${derived.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  length: ${derived.length} bytes');
  print('  match SageMath? ${derived.map((b) => b.toRadixString(16).padLeft(2, '0')).join() == '55c8e6fdcbb611ef67fb69b6245f688a372828f56b78b5f6006d389ee215f6ba'}');

  // Test 2: Shared secret berbeda = derived key berbeda?
  print('\nTest 2 - Shared secret berbeda = derived key berbeda?');
  final shared2 = Uint8List(32);
  final derived2 = HKDF.derive(ikm: shared2, info: info);
  print('  derived2: ${derived2.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  berbeda? ${derived.toString() != derived2.toString()}');

  // Test 3: Info berbeda = derived key berbeda?
  print('\nTest 3 - Info berbeda = derived key berbeda?');
  final info2 = Uint8List.fromList('X256189 auth key'.codeUnits);
  final derived3 = HKDF.derive(ikm: sharedSecret, info: info2);
  print('  derived3: ${derived3.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  berbeda? ${derived.toString() != derived3.toString()}');

  // Test 4: ECDH + HKDF end-to-end
  print('\nTest 4 - ECDH + HKDF end-to-end?');
  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final aliceKP = X256189.generateKeyPair(seedAlice);
  final bobKP = X256189.generateKeyPair(seedBob);

  final sharedAlice = X256189.computeSharedSecret(
    aliceKP['privateKey']!, bobKP['publicKey']!,
  );
  final sharedBob = X256189.computeSharedSecret(
    bobKP['privateKey']!, aliceKP['publicKey']!,
  );

  final keyAlice = HKDF.derive(ikm: sharedAlice!, info: info);
  final keyBob = HKDF.derive(ikm: sharedBob!, info: info);
  print('  Alice key: ${keyAlice.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Bob key:   ${keyBob.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  match? ${keyAlice.toString() == keyBob.toString()}');

  // Test 5: Output length 32 bytes?
  print('\nTest 5 - Output length 32 bytes?');
  print('  ${derived.length == 32}');
}