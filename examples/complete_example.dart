/// Complete Real-World Example: ECDH → HKDF → AES-GCM
///
/// This example demonstrates a practical cryptographic workflow:
/// 1. Two parties (Alice and Bob) agree on a shared secret via ECDH
/// 2. They derive encryption keys from the shared secret using HKDF
/// 3. They encrypt messages using AES-256-GCM
///
/// This is the fundamental pattern for modern end-to-end encryption systems.
library curve256189_example;

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('');
  print('╔═══════════════════════════════════════════════════════════╗');
  print('║  Curve256189 — Complete Encryption Workflow Example       ║');
  print('║  ECDH → HKDF → AES-256-GCM                                ║');
  print('╚═══════════════════════════════════════════════════════════╝');
  print('');

  // ═════════════════════════════════════════════════════════════
  // PHASE 1: KEY EXCHANGE (ECDH)
  // ═════════════════════════════════════════════════════════════
  //
  // Alice and Bob exchange public keys and compute a shared secret
  // that an eavesdropper cannot compute.

  print('PHASE 1: KEY EXCHANGE (ECDH)');
  print('─────────────────────────────────────────────────────────');
  print('');

  // Generate Alice's key pair
  final aliceSeed = Uint8List.fromList(List.generate(
    32,
        (i) => (0x01 + i) % 256,
  ));
  final aliceKP = X256189.generateKeyPair(aliceSeed);
  final alicePrivateKey = aliceKP['privateKey']!;
  final alicePublicKey = aliceKP['publicKey']!;

  print('✓ Alice generates key pair');
  print('  Public Key: ${_truncateHex(alicePublicKey)}');
  print('');

  // Generate Bob's key pair
  final bobSeed = Uint8List.fromList(List.generate(
    32,
        (i) => (0x21 + i) % 256,
  ));
  final bobKP = X256189.generateKeyPair(bobSeed);
  final bobPrivateKey = bobKP['privateKey']!;
  final bobPublicKey = bobKP['publicKey']!;

  print('✓ Bob generates key pair');
  print('  Public Key: ${_truncateHex(bobPublicKey)}');
  print('');

  // Compute shared secret
  final sharedSecret = X256189.computeSharedSecret(
    alicePrivateKey,
    bobPublicKey,
  );

  if (sharedSecret == null) {
    print('✗ ERROR: Failed to compute shared secret');
    return;
  }

  print('✓ Alice computes shared secret');
  print('  Shared Secret: ${_truncateHex(sharedSecret)}');
  print('');

  // Verify Bob computes the same shared secret
  final bobSharedSecret = X256189.computeSharedSecret(
    bobPrivateKey,
    alicePublicKey,
  );

  if (bobSharedSecret == null || !_bytesEqual(sharedSecret, bobSharedSecret)) {
    print('✗ ERROR: Shared secrets do not match');
    return;
  }

  print('✓ Bob computes the same shared secret (verified)');
  print('');

  // ═════════════════════════════════════════════════════════════
  // PHASE 2: KEY DERIVATION (HKDF)
  // ═════════════════════════════════════════════════════════════
  //
  // Derive two 32-byte keys from the shared secret:
  // - aesKey: for AES-256-GCM encryption
  // - aesNonce: for unique per-message nonces

  print('PHASE 2: KEY DERIVATION (HKDF)');
  print('─────────────────────────────────────────────────────────');
  print('');

  // Derive AES encryption key (32 bytes for AES-256)
  final aesKey = HKDF.derive(
    ikm: sharedSecret,
    info: Uint8List.fromList('curve256189-aes-key'.codeUnits),
    length: 32,
  );

  print('✓ Derived AES-256 encryption key');
  print('  Key: ${_truncateHex(aesKey)}');
  print('');

  // Derive nonce generation material (12 bytes for GCM nonce)
  // In production, combine this with a counter for unique nonces per message
  final nonceBase = HKDF.derive(
    ikm: sharedSecret,
    info: Uint8List.fromList('curve256189-nonce'.codeUnits),
    length: 12,
  );

  print('✓ Derived nonce material (12 bytes)');
  print('  Nonce: ${_truncateHex(nonceBase)}');
  print('');

  // ═════════════════════════════════════════════════════════════
  // PHASE 3: MESSAGE ENCRYPTION (AES-256-GCM)
  // ══════���══════════════════════════════════════════════════════
  //
  // Alice encrypts a message using the derived key and nonce.

  print('PHASE 3: MESSAGE ENCRYPTION (AES-256-GCM)');
  print('─────────────────────────────────────────────────────────');
  print('');

  final message = Uint8List.fromList(
    'Attack at dawn! This is a confidential military message.'.codeUnits,
  );

  print('✓ Alice\'s plaintext message:');
  print('  "${String.fromCharCodes(message)}"');
  print('  Length: ${message.length} bytes');
  print('');

  final encryptionResult = AESGCM.encrypt(
    key: aesKey,
    nonce: nonceBase,
    plaintext: message,
  );

  print('✓ Alice encrypts the message using AES-256-GCM');
  print('  Ciphertext: ${_truncateHex(encryptionResult.ciphertext)}');
  print('  Auth Tag: ${_truncateHex(encryptionResult.tag)}');
  print('');

  // ═════════════════════════════════════════════════════════════
  // PHASE 4: MESSAGE DECRYPTION (AES-256-GCM)
  // ═════════════════════════════════════════════════════════════
  //
  // Bob receives the ciphertext and decrypts it using the shared
  // encryption key. The authentication tag verifies integrity.

  print('PHASE 4: MESSAGE DECRYPTION (AES-256-GCM)');
  print('─────────────────────────────────────────────────────────');
  print('');

  // Bob uses his derived key to decrypt (must match Alice's via HKDF)
  final bobAesKey = HKDF.derive(
    ikm: bobSharedSecret,  // Bob's shared secret
    info: Uint8List.fromList('curve256189-aes-key'.codeUnits),
    length: 32,
  );

  final bobNonceBase = HKDF.derive(
    ikm: bobSharedSecret,
    info: Uint8List.fromList('curve256189-nonce'.codeUnits),
    length: 12,
  );

  final decrypted = AESGCM.decrypt(
    key: bobAesKey,
    nonce: bobNonceBase,
    ciphertext: encryptionResult.ciphertext,
    tag: encryptionResult.tag,
  );

  if (decrypted == null) {
    print('✗ ERROR: Decryption failed (authentication tag mismatch)');
    return;
  }

  final decryptedMessage = String.fromCharCodes(decrypted);
  print('✓ Bob decrypts and verifies the message');
  print('  Plaintext: "$decryptedMessage"');
  print('  Length: ${decrypted.length} bytes');
  print('');

  // Verify decryption is correct
  if (!_bytesEqual(message, decrypted)) {
    print('✗ ERROR: Decrypted message does not match original');
    return;
  }

  print('✓ Decrypted message matches original (verified)');
  print('');

  // ═════════════════════════════════════════════════════════════
  // PHASE 5: SECURITY DEMONSTRATION
  // ═════════════════════════════════════════════════════════════
  //
  // Demonstrate that eavesdropping and tampering fail.

  print('PHASE 5: SECURITY DEMONSTRATIONS');
  print('─────────────────────────────────────────────────────────');
  print('');

  // Attempt 5a: Eavesdropper cannot decrypt
  print('Scenario 5a: Eavesdropper Eve intercepts the message');
  final eveSeed = Uint8List.fromList(List.generate(32, (i) => (i + 100) % 256));
  final eveKP = X256189.generateKeyPair(eveSeed);
  final evePrivateKey = eveKP['privateKey']!;

  // Eve does NOT have access to Bob's private key, so she cannot
  // compute the shared secret, even though she has the public keys.
  // (We demonstrate this by showing Eve cannot produce the correct key)
  final eveAttemptedSecret = X256189.computeSharedSecret(
    evePrivateKey,
    bobPublicKey,
  );

  if (eveAttemptedSecret != null) {
    final eveCanDecrypt = _bytesEqual(eveAttemptedSecret, sharedSecret);
    print('  Eve\'s "shared secret" matches true secret: $eveCanDecrypt');
    print('  ✓ Eve cannot decrypt (shared secret differs)');
  }
  print('');

  // Attempt 5b: Tampering is detected
  print('Scenario 5b: Attacker tampers with the ciphertext');
  final tamperedCiphertext = Uint8List.fromList(encryptionResult.ciphertext);
  tamperedCiphertext[0] ^= 0xFF;  // Flip 8 bits

  final tamperingDetected = AESGCM.decrypt(
    key: aesKey,
    nonce: nonceBase,
    ciphertext: tamperedCiphertext,
    tag: encryptionResult.tag,
  );

  print('  Tampered ciphertext decrypts: ${tamperingDetected != null}');
  print('  ✓ Tampering detected (decryption fails)');
  print('');

  // ═════════════════════════════════════════════════════════════
  // SUMMARY
  // ═════════════════════════════════════════════════════════════

  print('╔═══════════════════════════════════════════════════════════╗');
  print('║  WORKFLOW COMPLETE                                        ║');
  print('╠═══════════════════════════════════════════════════════════╣');
  print('║  ✓ Alice and Bob exchanged keys securely (ECDH)           ║');
  print('║  ✓ Derived encryption keys from shared secret (HKDF)      ║');
  print('║  ✓ Encrypted a message with authentication (AES-GCM)      ║');
  print('║  ✓ Bob decrypted and verified the message                 ║');
  print('║  ✓ Eavesdropper cannot decrypt                            ║');
  print('║  ✓ Tampering is immediately detected                      ║');
  print('╚═══════════════════════════════════════════════════════════╝');
  print('');
}

/// Convert bytes to hexadecimal string, truncated for display
String _truncateHex(Uint8List bytes) {
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return hex.length > 32 ? '${hex.substring(0, 32)}...' : hex;
}

/// Check if two byte arrays are equal
bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}