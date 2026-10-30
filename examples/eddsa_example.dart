/// EdDSA Digital Signature Examples
///
/// This example demonstrates how to use Curve256189's EdDSA implementation
/// for creating and verifying digital signatures.
///
/// EdDSA (Edwards-Curve Digital Signature Algorithm) provides:
/// - Deterministic signatures (same message always produces same signature)
/// - Strong security properties based on elliptic curve mathematics
/// - Protection against timing attacks via constant-time operations
library curve256189_example;

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('═══════════════════════════════════════════════════════════');
  print('  Curve256189 — EdDSA Digital Signature Example');
  print('═══════════════════════════════════════════════════════════');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 1: Generate an EdDSA Key Pair
  // ─────────────────────────────────────────────────────────────
  //
  // EdDSA requires a 32-byte seed as input. This seed is used to
  // deterministically derive the private and public keys.
  print('Step 1: Generate EdDSA Key Pair');
  print('───────────────────────────────');

  final seed = Uint8List.fromList([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
  ]);

  final keyPair = EdDSA.generateKeyPair(seed);
  final privateKey = keyPair['privateKey']!;
  final publicKey = keyPair['publicKey']!;

  print('Private Key (seed): ${_toHex(privateKey)}');
  print('Public Key:         ${_toHex(publicKey)}');
  print('Public Key Length:  ${publicKey.length} bytes');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 2: Sign a Message
  // ─────────────────────────────────────────────────────────────
  //
  // EdDSA.sign() produces a deterministic signature. Given the same
  // message and private key, the signature will always be identical.
  // This prevents nonce reuse vulnerabilities present in ECDSA.
  print('Step 2: Sign a Message');
  print('──────────────────────');

  final message = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  print('Message: "Hello Curve256189!"');
  print('Message Length: ${message.length} bytes');
  print('');

  final signature = EdDSA.sign(message, privateKey);
  print('Signature: ${_toHex(signature)}');
  print('Signature Length: ${signature.length} bytes (R: 33 + S: 32)');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 3: Verify the Signature
  // ─────────────────────────────────────────────────────────────
  //
  // EdDSA.verify() checks that a signature is valid for a given
  // message and public key. It returns true only if the signature
  // is mathematically valid and corresponds to the message.
  print('Step 3: Verify the Signature');
  print('────────────────────────────');

  final isValid = EdDSA.verify(message, signature, publicKey);
  print('Signature Valid: $isValid');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 4: Demonstrate Signature Rejection
  // ─────────────────────────────────────────────────────────────
  //
  // Any tampering with the message, signature, or public key will
  // cause verification to fail. This ensures integrity.
  print('Step 4: Demonstrate Rejection of Invalid Signatures');
  print('────────────────────────────────────────────────────');

  // Attempt 4a: Wrong message
  final wrongMessage = Uint8List.fromList('Wrong message'.codeUnits);
  final isValidWrongMsg = EdDSA.verify(wrongMessage, signature, publicKey);
  print('  4a) Wrong message: $isValidWrongMsg (expected: false)');

  // Attempt 4b: Tampered signature
  final tamperedSignature = Uint8List.fromList(signature);
  tamperedSignature[0] ^= 0x01;  // Flip one bit
  final isValidTampered = EdDSA.verify(message, tamperedSignature, publicKey);
  print('  4b) Tampered signature: $isValidTampered (expected: false)');

  // Attempt 4c: Different public key
  final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 100));
  final keyPair2 = EdDSA.generateKeyPair(seed2);
  final isValidWrongKey = EdDSA.verify(message, signature, keyPair2['publicKey']!);
  print('  4c) Wrong public key: $isValidWrongKey (expected: false)');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 5: Determinism Property
  // ─────────────────────────────────────────────────────────────
  //
  // EdDSA is deterministic: signing the same message twice produces
  // identical signatures. This prevents accidental nonce reuse.
  print('Step 5: EdDSA Determinism Property');
  print('──────────────────────────────────');

  final signature2 = EdDSA.sign(message, privateKey);
  final areSignaturesIdentical = _bytesEqual(signature, signature2);
  print('Second Signature: ${_toHex(signature2)}');
  print('Signatures Match: $areSignaturesIdentical (expected: true)');
  print('');

  print('═══════════════════════════════════════════════════════════');
  print('  EdDSA Example Completed Successfully');
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