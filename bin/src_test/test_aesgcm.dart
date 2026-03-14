// test_aesgcm.dart
// AES-256-GCM tests per NIST SP 800-38D
import 'dart:typed_data';
import '../src/aesgcm.dart';
import '../src/x256189.dart';
import '../src/hkdf.dart';

void main() {
  print('=== Test AES-256-GCM Curve256189 ===');

  // Test 1: NIST test vector — empty plaintext
  // Source: NIST CAVS AES-GCM test vectors
  print('\nTest 1 - NIST test vector (empty plaintext)?');
  final key1 = Uint8List.fromList(List.filled(32, 0));
  final nonce1 = Uint8List.fromList(List.filled(12, 0));
  final result1 = AESGCM.encrypt(
    key: key1,
    nonce: nonce1,
    plaintext: Uint8List(0),
  );
  print('  tag: ${result1.tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  match NIST? ${result1.tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join() == '530f8afbc74536b9a963b4f1c4cb738b'}');

  // Test 2: Encrypt and decrypt round-trip
  print('\nTest 2 - Encrypt/decrypt round-trip?');
  final key2 = Uint8List.fromList(List.generate(32, (i) => i));
  final nonce2 = Uint8List.fromList(List.generate(12, (i) => i));
  final plaintext2 = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  final result2 = AESGCM.encrypt(
    key: key2,
    nonce: nonce2,
    plaintext: plaintext2,
  );
  final decrypted2 = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: result2.ciphertext,
    tag: result2.tag,
  );
  print('  plaintext:  ${String.fromCharCodes(plaintext2)}');
  print('  ciphertext: ${result2.ciphertext.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  decrypted:  ${String.fromCharCodes(decrypted2!)}');
  print('  match? ${plaintext2.toString() == decrypted2.toString()}');

  // Test 3: Tampered ciphertext rejected?
  print('\nTest 3 - Tampered ciphertext rejected?');
  final tamperedCiphertext = Uint8List.fromList(result2.ciphertext);
  tamperedCiphertext[0] ^= 0x01;
  final decrypted3 = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: tamperedCiphertext,
    tag: result2.tag,
  );
  print('  tampered result null? ${decrypted3 == null}');

  // Test 4: Tampered tag rejected?
  print('\nTest 4 - Tampered tag rejected?');
  final tamperedTag = Uint8List.fromList(result2.tag);
  tamperedTag[0] ^= 0x01;
  final decrypted4 = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: result2.ciphertext,
    tag: tamperedTag,
  );
  print('  tampered tag result null? ${decrypted4 == null}');

  // Test 5: AAD (Additional Authenticated Data)
  print('\nTest 5 - AAD authentication?');
  final aad = Uint8List.fromList('Curve256189 AAD'.codeUnits);
  final result5 = AESGCM.encrypt(
    key: key2,
    nonce: nonce2,
    plaintext: plaintext2,
    aad: aad,
  );
  // Decrypt with correct AAD
  final decrypted5 = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: result5.ciphertext,
    tag: result5.tag,
    aad: aad,
  );
  // Decrypt with wrong AAD
  final wrongAad = Uint8List.fromList('Wrong AAD'.codeUnits);
  final decrypted5wrong = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: result5.ciphertext,
    tag: result5.tag,
    aad: wrongAad,
  );
  print('  correct AAD: ${decrypted5 != null}');
  print('  wrong AAD rejected? ${decrypted5wrong == null}');

  // Test 6: ECDH + HKDF + AES-GCM end-to-end
  print('\nTest 6 - ECDH + HKDF + AES-GCM end-to-end?');
  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final aliceKP = X256189.generateKeyPair(seedAlice);
  final bobKP = X256189.generateKeyPair(seedBob);

  // Shared secret
  final sharedAlice = X256189.computeSharedSecret(
    aliceKP['privateKey']!, bobKP['publicKey']!,
  );

  // Derive AES key + nonce via HKDF
  final aesKey = HKDF.derive(
    ikm: sharedAlice!,
    info: Uint8List.fromList('Curve256189 AES key'.codeUnits),
    length: 32,
  );
  final aesNonce = HKDF.derive(
    ikm: sharedAlice,
    info: Uint8List.fromList('Curve256189 AES nonce'.codeUnits),
    length: 12,
  );

  // Alice encrypts message
  final message = Uint8List.fromList('Hello Bob! — Curve256189'.codeUnits);
  final encrypted = AESGCM.encrypt(
    key: aesKey,
    nonce: aesNonce,
    plaintext: message,
  );

  // Bob derives same key and decrypts
  final sharedBob = X256189.computeSharedSecret(
    bobKP['privateKey']!, aliceKP['publicKey']!,
  );
  final aesKeyBob = HKDF.derive(
    ikm: sharedBob!,
    info: Uint8List.fromList('Curve256189 AES key'.codeUnits),
    length: 32,
  );
  final aesNonceBob = HKDF.derive(
    ikm: sharedBob,
    info: Uint8List.fromList('Curve256189 AES nonce'.codeUnits),
    length: 12,
  );
  final decryptedMsg = AESGCM.decrypt(
    key: aesKeyBob,
    nonce: aesNonceBob,
    ciphertext: encrypted.ciphertext,
    tag: encrypted.tag,
  );
  print('  Alice message: ${String.fromCharCodes(message)}');
  print('  Bob decrypted: ${String.fromCharCodes(decryptedMsg!)}');
  print('  match? ${message.toString() == decryptedMsg.toString()}');
}