// test_x256189.dart

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: X256189 ECDH + EdDSA Curve256189 ===');

  // Alice and Bob seeds
  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob = Uint8List.fromList(List.generate(32, (i) => i + 33));

  // Test case 1: Key pair generation
  print('');
  print('Test 1 - Key Generation:');
  final aliceKP = X256189.generateKeyPair(seedAlice);
  final bobKP = X256189.generateKeyPair(seedBob);
  print('  Alice PK: ${aliceKP['publicKey']!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Bob PK:   ${bobKP['publicKey']!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  PK length: ${aliceKP['publicKey']!.length} bytes');

  // Test case 2: Shared secret computed by Alice and Bob should match
  print('');
  print('Test 2 - Does Alice\'s shared secret equal Bob\'s shared secret?');
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

  // Test case 3: Different seeds produce different shared secrets
  print('');
  print('Test 3 - Do different seeds produce different shared secrets?');
  final seedEve = Uint8List.fromList(List.generate(32, (i) => i + 65));
  final eveKP = X256189.generateKeyPair(seedEve);
  final sharedEve = X256189.computeSharedSecret(
    eveKP['privateKey']!,
    aliceKP['publicKey']!,
  );
  print('  Eve shared: ${sharedEve!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Eve != Alice? ${sharedEve.toString() != sharedAlice.toString()}');

  // Test case 4: Invalid public key should be rejected
  print('');
  print('Test 4 - Is an invalid public key rejected?');
  final invalidPK = Uint8List(32);
  final result = X256189.computeSharedSecret(aliceKP['privateKey']!, invalidPK);
  print('  invalid PK result is null? ${result == null}');

  // Test case 5: Public key length should be exactly 32 bytes
  print('');
  print('Test 5 - Is the public key length 32 bytes?');
  print('  ${aliceKP['publicKey']!.length == 32}');

  // Test case 6: EdDSA key pair generated from the same seed
  print('');
  print('Test 6 - EdDSA key pair from the same seed:');
  final aliceEdKP = EdDSA.generateKeyPair(seedAlice);
  final bobEdKP = EdDSA.generateKeyPair(seedBob);
  print('  Alice EdDSA PK: ${aliceEdKP['publicKey']!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Bob EdDSA PK:   ${bobEdKP['publicKey']!.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  PK different from ECDH PK? ${aliceEdKP['publicKey']!.toString() != aliceKP['publicKey']!.toString()}');

  // Test case 7: Alice signs a message, Bob verifies
  print('');
  print('Test 7 - Alice signs a message, then Bob verifies:');
  final message = Uint8List.fromList('Hello X256189!'.codeUnits);
  final signature = EdDSA.sign(message, aliceEdKP['privateKey']!);
  final verified = EdDSA.verify(message, signature, aliceEdKP['publicKey']!);
  print('  Signature: ${signature.map((b) => b.toRadixString(16).padLeft(2, '0')).join().substring(0, 32)}...');
  print('  Verified? $verified');

  // Test case 8: Tampered message should fail verification
  print('');
  print('Test 8 - Does a tampered message fail verification?');
  final tamperedMessage = Uint8List.fromList('Hello X256189?'.codeUnits);
  final verifiedTampered = EdDSA.verify(tamperedMessage, signature, aliceEdKP['publicKey']!);
  print('  Verified tampered? $verifiedTampered');

  // Test case 9: Combined ECDH shared secret + EdDSA signature
  print('');
  print('Test 9 - Combined: ECDH shared secret with EdDSA signature:');
  final combinedMessage = Uint8List.fromList([...sharedAlice, ...message]);
  final combinedSig = EdDSA.sign(combinedMessage, aliceEdKP['privateKey']!);
  final combinedVerified = EdDSA.verify(combinedMessage, combinedSig, aliceEdKP['publicKey']!);
  print('  Combined verify? $combinedVerified');
}