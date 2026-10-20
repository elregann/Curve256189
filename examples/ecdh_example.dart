/// ECDH Key Exchange Example
///
/// This example demonstrates how to use Curve256189's X256189 implementation
/// for secure key exchange between two parties (Alice and Bob).
///
/// ECDH (Elliptic Curve Diffie-Hellman) enables:
/// - Two parties to agree on a shared secret over an insecure channel
/// - The shared secret can then be used for symmetric encryption (e.g., AES-GCM)
/// - An eavesdropper cannot compute the shared secret without a private key
library curve256189_example;

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('═══════════════════════════════════════════════════════════');
  print('  Curve256189 — ECDH Key Exchange Example');
  print('═══════════════════════════════════════════════════════════');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 1: Alice Generates Her Key Pair
  // ─────────────────────────────────────────────────────────────
  //
  // Each party (Alice and Bob) must generate their own key pair.
  // The private key must be kept secret; the public key is shared.
  print('Step 1: Alice Generates Her Key Pair');
  print('────────────────────────────────────');

  final aliceSeed = Uint8List.fromList([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  ]);

  final aliceKP = X256189.generateKeyPair(aliceSeed);
  final alicePrivateKey = aliceKP['privateKey']!;
  final alicePublicKey = aliceKP['publicKey']!;

  print('Alice Private Key: ${_toHex(alicePrivateKey.sublist(0, 8))}...');
  print('Alice Public Key:  ${_toHex(alicePublicKey)}');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 2: Bob Generates His Key Pair
  // ─────────────────────────────────────────────────────────────
  print('Step 2: Bob Generates His Key Pair');
  print('───────────────────────────────────');

  final bobSeed = Uint8List.fromList([
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
  ]);

  final bobKP = X256189.generateKeyPair(bobSeed);
  final bobPrivateKey = bobKP['privateKey']!;
  final bobPublicKey = bobKP['publicKey']!;

  print('Bob Private Key: ${_toHex(bobPrivateKey.sublist(0, 8))}...');
  print('Bob Public Key:  ${_toHex(bobPublicKey)}');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 3: Alice Computes the Shared Secret
  // ──────���──────────────────────────────────────────────────────
  //
  // Alice uses her private key and Bob's public key to compute
  // a shared secret. Mathematically: sharedSecret = alicePrivate * bobPublic
  print('Step 3: Alice Computes Shared Secret');
  print('────────────────────────────────────');

  final sharedSecretAlice = X256189.computeSharedSecret(
    alicePrivateKey,
    bobPublicKey,
  );

  if (sharedSecretAlice == null) {
    print('ERROR: Failed to compute shared secret (invalid key)');
    return;
  }

  print('Shared Secret: ${_toHex(sharedSecretAlice)}');
  print('Shared Secret Length: ${sharedSecretAlice.length} bytes');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 4: Bob Computes the Shared Secret
  // ─────────────────────────────────────────────────────────────
  //
  // Bob uses his private key and Alice's public key to compute
  // the shared secret. Mathematically: sharedSecret = bobPrivate * alicePublic
  // Due to the mathematical properties of ECDH, this MUST equal Alice's result.
  print('Step 4: Bob Computes Shared Secret');
  print('──────────────────────────────────');

  final sharedSecretBob = X256189.computeSharedSecret(
    bobPrivateKey,
    alicePublicKey,
  );

  if (sharedSecretBob == null) {
    print('ERROR: Failed to compute shared secret (invalid key)');
    return;
  }

  print('Shared Secret: ${_toHex(sharedSecretBob)}');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 5: Verify the Shared Secrets Match
  // ─────────────────────────────────────────────────────────────
  //
  // The shared secrets computed by Alice and Bob must be identical.
  // This is the mathematical guarantee that ECDH provides.
  print('Step 5: Verify Shared Secrets Match');
  print('───────────────────────────────────');

  final secretsMatch = _bytesEqual(sharedSecretAlice, sharedSecretBob);
  print('Secrets Match: $secretsMatch (expected: true)');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 6: Demonstrate Security Against Eavesdropping
  // ─────────────────────────────────────────────────────────────
  //
  // An eavesdropper (Eve) who observes Alice's and Bob's public keys
  // cannot compute the shared secret without one of their private keys.
  print('Step 6: Demonstrate Eavesdropping Resistance');
  print('───────────────────────────────────────────');

  final eveSeed = Uint8List.fromList(List.generate(32, (i) => i + 100));
  final eveKP = X256189.generateKeyPair(eveSeed);
  final evePrivateKey = eveKP['privateKey']!;

  // Eve tries to compute a "shared secret" using Bob's public key
  // This will NOT match the true shared secret
  final eveSecret = X256189.computeSharedSecret(evePrivateKey, bobPublicKey);

  if (eveSecret != null) {
    final eveMatchesTrue = _bytesEqual(eveSecret, sharedSecretAlice);
    print('Eve\'s "Shared Secret": ${_toHex(eveSecret)}');
    print('Matches True Secret: $eveMatchesTrue (expected: false)');
  }
  print('');

  print('═══════════════════════════════════════════════════════════');
  print('  ECDH Example Completed Successfully');
  print('═══════════════════════════════════════════════════════════');
}

/// Convert bytes to hexadecimal string for display
String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Check if two byte arrays are equal
bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}