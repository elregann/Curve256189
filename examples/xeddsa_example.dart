/// XEdDSA Digital Signature Examples
///
/// This example demonstrates how to use Curve256189's XEdDSA implementation
/// for creating and verifying digital signatures.
///
/// XEdDSA is an x-only Schnorr-style signature scheme built on the
/// Montgomery form of Curve256189. It provides:
/// - 32-byte x-only public keys
/// - 64-byte signatures (x(R) || s)
/// - Deterministic signatures (same message always produces same signature)
/// - No malleability: (x(R), n - s) and (x(R), s + n) are rejected
library curve256189_example;

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('═══════════════════════════════════════════════════════════');
  print('  Curve256189 — XEdDSA Digital Signature Example');
  print('═══════════════════════════════════════════════════════════');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 1: Generate an XEdDSA Key Pair
  // ─────────────────────────────────────────────────────────────
  //
  // XEdDSA requires a 32-byte seed as input. The public key is the
  // x-coordinate of the derived point and matches X256189 exactly.
  print('Step 1: Generate XEdDSA Key Pair');
  print('───────────────────────────────');

  final seed = Uint8List.fromList([
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    0x20,
  ]);

  final keyPair = XEdDSA.generateKeyPair(seed);
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
  // XEdDSA.sign() produces a deterministic signature. Given the same
  // message and private key, the signature will always be identical.
  // This prevents nonce reuse vulnerabilities present in ECDSA.
  print('Step 2: Sign a Message');
  print('──────────────────────');

  final message = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  print('Message: "Hello Curve256189!"');
  print('Message Length: ${message.length} bytes');
  print('');

  final signature = XEdDSA.sign(message, privateKey);
  print('Signature: ${_toHex(signature)}');
  print('Signature Length: ${signature.length} bytes (x(R): 32 + s: 32)');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 3: Verify the Signature
  // ─────────────────────────────────────────────────────────────
  //
  // XEdDSA.verify() checks the exact full-point equation
  //     [s]G == R + [h]P
  // and rejects malformed, non-canonical, low-order, and mixed-order keys.
  print('Step 3: Verify the Signature');
  print('────────────────────────────');

  final isValid = XEdDSA.verify(message, signature, publicKey);
  print('Signature Valid: $isValid');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 4: Demonstrate Signature Rejection
  // ─────────────────────────────────────────────────────────────
  print('Step 4: Demonstrate Rejection of Invalid Signatures');
  print('────────────────────────────────────────────────────');

  // Attempt 4a: Wrong message
  final wrongMessage = Uint8List.fromList('Wrong message'.codeUnits);
  final isValidWrongMsg = XEdDSA.verify(wrongMessage, signature, publicKey);
  print('  4a) Wrong message: $isValidWrongMsg (expected: false)');

  // Attempt 4b: Tampered signature
  final tamperedSignature = Uint8List.fromList(signature);
  tamperedSignature[0] ^= 0x01;
  final isValidTampered = XEdDSA.verify(message, tamperedSignature, publicKey);
  print('  4b) Tampered signature: $isValidTampered (expected: false)');

  // Attempt 4c: Different public key
  final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 100));
  final keyPair2 = XEdDSA.generateKeyPair(seed2);
  final isValidWrongKey =
      XEdDSA.verify(message, signature, keyPair2['publicKey']!);
  print('  4c) Wrong public key: $isValidWrongKey (expected: false)');

  // Attempt 4d: Malleated s -> n - s
  final n = Curve256189Params.n;
  final xR = Uint8List.fromList(signature.sublist(0, 32));
  final s =
      XEdDSA.decodeLittleEndian(Uint8List.fromList(signature.sublist(32)));
  final malleated = Uint8List.fromList([
    ...xR,
    ...XEdDSA.encodeScalar((n - s) % n),
  ]);
  final isValidMalleated = XEdDSA.verify(message, malleated, publicKey);
  print('  4d) Malleated (n - s): $isValidMalleated (expected: false)');
  print('');

  // ─────────────────────────────────────────────────────────────
  // Step 5: Determinism Property
  // ─────────────────────────────────────────────────────────────
  print('Step 5: XEdDSA Determinism Property');
  print('──────────────────────────────────');

  final signature2 = XEdDSA.sign(message, privateKey);
  final areSignaturesIdentical = _bytesEqual(signature, signature2);
  print('Second Signature: ${_toHex(signature2)}');
  print('Signatures Match: $areSignaturesIdentical (expected: true)');
  print('');

  print('═══════════════════════════════════════════════════════════');
  print('  XEdDSA Example Completed Successfully');
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
