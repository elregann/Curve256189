// test_aesgcm.dart

// AES-256-GCM tests per NIST SP 800-38D
import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: AES-256-GCM Curve256189 ===');

  // Test case 1: NIST test vector for empty plaintext
  // Source: NIST CAVS AES-GCM test vectors
  print('');
  print('Test 1 - NIST test vector (empty plaintext):');
  final key1 = Uint8List.fromList(List.filled(32, 0));
  final nonce1 = Uint8List.fromList(List.filled(12, 0));
  final result1 = AESGCM.encrypt(
    key: key1,
    nonce: nonce1,
    plaintext: Uint8List(0),
  );
  final tagHex = result1.tag.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  print('  tag: $tagHex');
  print('  matches NIST? ${tagHex == '530f8afbc74536b9a963b4f1c4cb738b'}');

  // Test case 2: Encrypt and decrypt round-trip
  print('');
  print('Test 2 - Encrypt/decrypt round-trip:');
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

  // Test case 3: Tampered ciphertext should be rejected
  print('');
  print('Test 3 - Tampered ciphertext rejected:');
  final tamperedCiphertext = Uint8List.fromList(result2.ciphertext);
  tamperedCiphertext[0] ^= 0x01;
  final decrypted3 = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: tamperedCiphertext,
    tag: result2.tag,
  );
  print('  tampered result is null? ${decrypted3 == null}');

  // Test case 4: Tampered tag should be rejected
  print('');
  print('Test 4 - Tampered tag rejected:');
  final tamperedTag = Uint8List.fromList(result2.tag);
  tamperedTag[0] ^= 0x01;
  final decrypted4 = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: result2.ciphertext,
    tag: tamperedTag,
  );
  print('  tampered tag result is null? ${decrypted4 == null}');

  // Test case 5: AAD (Additional Authenticated Data) authentication
  print('');
  print('Test 5 - AAD authentication:');
  final aad = Uint8List.fromList('Curve256189 AAD'.codeUnits);
  final result5 = AESGCM.encrypt(
    key: key2,
    nonce: nonce2,
    plaintext: plaintext2,
    aad: aad,
  );
  // Decrypt with the correct AAD
  final decrypted5 = AESGCM.decrypt(
    key: key2,
    nonce: nonce2,
    ciphertext: result5.ciphertext,
    tag: result5.tag,
    aad: aad,
  );
  // Decrypt with an incorrect AAD
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

  // Test case 6: ECDH + HKDF + AES-GCM end-to-end
  print('');
  print('Test 6 - ECDH + HKDF + AES-GCM end-to-end:');
  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final aliceKP = X256189.generateKeyPair(seedAlice);
  final bobKP = X256189.generateKeyPair(seedBob);

  // Compute shared secret using X25519-style Diffie-Hellman
  final sharedAlice = X256189.computeSharedSecret(
    aliceKP['privateKey']!, bobKP['publicKey']!,
  );

  // Derive AES key and nonce using HKDF
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

  // Alice encrypts a message
  final message = Uint8List.fromList('Hello Bob! from Curve256189'.codeUnits);
  final encrypted = AESGCM.encrypt(
    key: aesKey,
    nonce: aesNonce,
    plaintext: message,
  );

  // Bob derives the same key and decrypts the message
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