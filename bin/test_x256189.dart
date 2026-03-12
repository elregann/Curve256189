// test_x256189.dart
import 'src/x256189.dart';
import 'dart:typed_data';

void main() {
  print('=== Test X256189 ECDH Curve256189 ===');

  // Seed Alice dan Bob
  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob = Uint8List.fromList(List.generate(32, (i) => i + 33));

  // Test 1: Key generation
  print('\nTest 1 - Key Generation:');
  final aliceKP = X256189.generateKeyPair(seedAlice);
  final bobKP = X256189.generateKeyPair(seedBob);
  print('  Alice PK: ${aliceKP['publicKey']!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Bob PK:   ${bobKP['publicKey']!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  PK length: ${aliceKP['publicKey']!.length} bytes');

  // Test 2: Shared secret match?
  print('\nTest 2 - Shared secret Alice == Bob?');
  final sharedAlice = X256189.computeSharedSecret(
    aliceKP['privateKey']!,
    bobKP['publicKey']!,
  );
  final sharedBob = X256189.computeSharedSecret(
    bobKP['privateKey']!,
    aliceKP['publicKey']!,
  );
  print('  Alice shared: ${sharedAlice!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Bob shared:   ${sharedBob!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  match? ${sharedAlice.toString() == sharedBob.toString()}');

  // Test 3: Seed berbeda = shared secret berbeda?
  print('\nTest 3 - Seed berbeda = shared secret berbeda?');
  final seedEve = Uint8List.fromList(List.generate(32, (i) => i + 65));
  final eveKP = X256189.generateKeyPair(seedEve);
  final sharedEve = X256189.computeSharedSecret(
    eveKP['privateKey']!,
    aliceKP['publicKey']!,
  );
  print('  Eve shared: ${sharedEve!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Eve != Alice? ${sharedEve.toString() != sharedAlice.toString()}');

  // Test 4: Public key invalid ditolak?
  print('\nTest 4 - Public key invalid ditolak?');
  final invalidPK = Uint8List(32);
  final result = X256189.computeSharedSecret(aliceKP['privateKey']!, invalidPK);
  print('  invalid PK result null? ${result == null}');

  // Test 5: Public key length 32 bytes?
  print('\nTest 5 - Public key length 32 bytes?');
  print('  ${aliceKP['publicKey']!.length == 32}');
}