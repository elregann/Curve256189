/// AES-256-GCM Authenticated Encryption Example
///
/// This example demonstrates how to use Curve256189's AES-GCM implementation
/// for encrypting and decrypting data with authentication.
///
/// AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) provides:
/// - Confidentiality: encrypted data cannot be read without the key
/// - Integrity: any tampering is detected
/// - Authenticity: the key holder is confirmed
/// All three properties in a single operation (AEAD).
library curve256189_example;

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('═══════════════════════════════════════════════════════════');
  print('  Curve256189 — AES-256-GCM Authenticated Encryption Example');
  print('═══════════════════════════════════════════════════════════');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 1: Prepare Encryption Key and Nonce
  // ─────────────────────────────────────────────────────────────
  //
  // AES-GCM requires:
  // - Key: 32 bytes (256-bit) for AES-256
  // - Nonce: 12 bytes (96-bit) per NIST recommendation
  //
  // WARNING: The nonce MUST NEVER be reused with the same key!
  // Nonce reuse completely breaks security.
  print('Step 1: Prepare Encryption Key and Nonce');
  print('─────────────────────────────────────────');

  final key = Uint8List.fromList([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ]);

  final nonce = Uint8List.fromList([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
  ]);

  print('Key Length: ${key.length} bytes (AES-256)');
  print('Key: ${_toHex(key)}');
  print('');
  print('Nonce Length: ${nonce.length} bytes (NIST recommended 96-bit)');
  print('Nonce: ${_toHex(nonce)}');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 2: Encrypt a Message
  // ─────────────────────────────────────────────────────────────
  //
  // AESGCM.encrypt() takes plaintext and produces:
  // - ciphertext: encrypted data (same length as plaintext)
  // - tag: 16-byte authentication tag
  print('Step 2: Encrypt a Message');
  print('───────────────────────────');

  final plaintext = Uint8List.fromList('This is a secret message!'.codeUnits);
  print('Plaintext: "This is a secret message!"');
  print('Plaintext Length: ${plaintext.length} bytes');
  print('');

  final encryptionResult = AESGCM.encrypt(
    key: key,
    nonce: nonce,
    plaintext: plaintext,
  );

  final ciphertext = encryptionResult.ciphertext;
  final tag = encryptionResult.tag;

  print('Ciphertext: ${_toHex(ciphertext)}');
  print('Ciphertext Length: ${ciphertext.length} bytes');
  print('');
  print('Authentication Tag: ${_toHex(tag)}');
  print('Tag Length: ${tag.length} bytes (128-bit)');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 3: Decrypt the Message
  // ─────────────────────────────────────────────────────────────
  //
  // AESGCM.decrypt() verifies the authentication tag and decrypts
  // only if the tag is valid. If tampering is detected, it returns null.
  print('Step 3: Decrypt the Message');
  print('────────────────────────────');

  final decrypted = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: ciphertext,
    tag: tag,
  );

  if (decrypted == null) {
    print('ERROR: Decryption failed (authentication tag mismatch)');
    return;
  }

  final decryptedMessage = String.fromCharCodes(decrypted);
  print('Decrypted Message: "$decryptedMessage"');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 4: Demonstrate Tampering Detection
  // ─────────────────────────────────────────────────────────────
  //
  // If ANY byte of the ciphertext or tag is modified, decryption fails.
  // This protects against attackers modifying encrypted messages.
  print('Step 4: Demonstrate Tampering Detection');
  print('───────────────────────────────────────');

  // Attempt 4a: Tamper with ciphertext
  final tamperedCiphertext = Uint8List.fromList(ciphertext);
  tamperedCiphertext[0] ^= 0x01;  // Flip one bit
  final result4a = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: tamperedCiphertext,
    tag: tag,
  );
  print('  4a) Tampered ciphertext: ${result4a == null ? 'REJECTED' : 'ERROR'}');

  // Attempt 4b: Tamper with authentication tag
  final tamperedTag = Uint8List.fromList(tag);
  tamperedTag[0] ^= 0x01;  // Flip one bit
  final result4b = AESGCM.decrypt(
    key: key,
    nonce: nonce,
    ciphertext: ciphertext,
    tag: tamperedTag,
  );
  print('  4b) Tampered tag: ${result4b == null ? 'REJECTED' : 'ERROR'}');

  // Attempt 4c: Wrong key
  final wrongKey = Uint8List.fromList(List.generate(32, (i) => (i + 100) % 256));
  final result4c = AESGCM.decrypt(
    key: wrongKey,
    nonce: nonce,
    ciphertext: ciphertext,
    tag: tag,
  );
  print('  4c) Wrong key: ${result4c == null ? 'REJECTED' : 'ERROR'}');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 5: Demonstrate Nonce Reuse Attack (INSECURE)
  // ─────────────────────────────────────────────────────────────
  //
  // NEVER reuse the same nonce with the same key!
  // Encrypting two different messages with the same key and nonce
  // completely breaks security.
  print('Step 5: Nonce Reuse Warning (Insecure)');
  print('──────────────────────────────────────');

  final plaintext2 = Uint8List.fromList('Different message'.codeUnits);

  // This is INSECURE — do not do this in real code!
  final result2 = AESGCM.encrypt(
    key: key,
    nonce: nonce,  // SAME nonce as before (INSECURE!)
    plaintext: plaintext2,
  );

  print('Plaintext 1: "This is a secret message!" (${plaintext.length} bytes)');
  print('Plaintext 2: "Different message" (${plaintext2.length} bytes)');
  print('');
  print('Ciphertext 1: ${_toHex(ciphertext.sublist(0, 8))}...');
  print('Ciphertext 2: ${_toHex(result2.ciphertext.sublist(0, 8))}...');
  print('');
  print('⚠️  WARNING: Reusing nonce allows an attacker to XOR the two');
  print('   plaintexts. Always generate a new random nonce per encryption!');
  print('');

  print('═══════════════════════════════════════════════════════════');
  print('  AES-GCM Example Completed Successfully');
  print('═══════════════════════════════════════════════════════════');
}

/// Convert bytes to hexadecimal string for display
String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}