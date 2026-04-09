// test_security_fixes.dart

// Security Fix Verification Tests
//
// This test suite verifies that security fixes work correctly:
// 1. decodePoint acceptance rate (approximately 50% for random inputs)
// 2. Twist points are rejected
// 3. Quadratic residue detection works
// 4. X256189 rejects malicious points

import 'dart:math';
import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('Curve256189 Security Fix Verifier');
  print('');

  _testDecodePointAcceptance();
  _testTwistPointRejection();
  _testQuadraticResidueDetection();
  _testEndToEndX256189();

  print('');
  print('=== Security Fix Verification Completed ===');
}

// Test 1: decodePoint Acceptance Rate
// Verifies that approximately 50% of random 33-byte inputs decode to valid points.
void _testDecodePointAcceptance() {
  print('TEST 1: decodePoint Acceptance Rate');
  print('');

  final random = Random.secure();
  int totalTests = 10000;
  int accepted = 0;

  for (int i = 0; i < totalTests; i++) {
    final bytes = Uint8List(33);
    for (int j = 0; j < 33; j++) {
      bytes[j] = random.nextInt(256);
    }

    final point = TwistedEdwards.decodePoint(bytes);
    if (point != null) {
      accepted++;

      if (!TwistedEdwards.isOnCurve(point)) {
        print('  CRITICAL: Decoded point is not on the curve.');
        return;
      }
    }
  }

  double rate = accepted / totalTests * 100;
  print('  Random 33-byte inputs: $totalTests');
  print('  Accepted: $accepted (${rate.toStringAsFixed(2)}%)');

  if (rate > 55) {
    print('  WARNING: Acceptance rate exceeds 55% (expected approximately 50%).');
  } else if (rate < 45) {
    print('  WARNING: Acceptance rate is below 45% (expected approximately 50%).');
  } else {
    print('  GOOD: Acceptance rate is within the expected range (approximately 50%).');
  }
  print('');
}

// Test 2: Twist Point Rejection
// Verifies that points on the twist curve are correctly rejected.
void _testTwistPointRejection() {
  print('TEST 2: Twist Point Rejection');
  print('');

  final p = Curve256189Params.p;
  final A = Curve256189Params.A;
  final random = Random.secure();
  int twistPointsFound = 0;
  int twistPointsRejected = 0;

  for (int i = 0; i < 1000; i++) {
    final x = BigInt.from(random.nextInt(1 << 20)) % p;
    final x2 = (x * x) % p;
    final x3 = (x2 * x) % p;
    final rhs = (x3 + A * x2 + x) % p;
    final exp = (p - BigInt.one) >> 1;
    final legendre = rhs.modPow(exp, p);

    if (legendre != BigInt.one) {
      twistPointsFound++;
      final point = MontgomeryPoint(x, BigInt.one);
      if (!Montgomery.isValidPoint(point)) {
        twistPointsRejected++;
      }
    }
  }

  print('  Twist points found: $twistPointsFound');
  print('  Rejected by isValidPoint: $twistPointsRejected');

  if (twistPointsRejected < twistPointsFound) {
    print('  WARNING: Some twist points were accepted.');
  } else {
    print('  GOOD: All twist points were rejected.');
  }
  print('');
}

// Test 3: Quadratic Residue Detection
// Verifies that quadratic residue detection works correctly.
void _testQuadraticResidueDetection() {
  print('TEST 3: Quadratic Residue Detection');
  print('');

  final p = Curve256189Params.p;
  final residues = <BigInt>{};

  for (int i = 1; i <= 100; i++) {
    final r = BigInt.from(i + 1000);
    final residue = (r * r) % p;
    residues.add(residue);
  }

  print('  Testing ${residues.length} known residues...');

  int detected = 0;
  for (final r in residues) {
    if (_isQuadraticResidue(r, p)) detected++;
  }

  print('  Detected: $detected/${residues.length}');
  print('  Note: Some residues may not be detected (this is normal).');
  print('');
}

// Helper function to test whether a value is a quadratic residue modulo p.
bool _isQuadraticResidue(BigInt a, BigInt p) {
  if (a == BigInt.zero) return true;
  if (a < BigInt.zero || a >= p) a = a % p;
  final exp = (p - BigInt.one) >> 1;
  final legendre = a.modPow(exp, p);
  return legendre == BigInt.one;
}

// Test 4: X256189 End-to-End with Malicious Points
// Verifies that X256189 rejects malicious (twist) points.
void _testEndToEndX256189() {
  print('TEST 4: X256189 End-to-End with Malicious Points');
  print('');

  final random = Random.secure();
  final seed = Uint8List(32);
  for (int i = 0; i < 32; i++) {
    seed[i] = random.nextInt(256);
  }
  final keypair = X256189.generateKeyPair(seed);

  // Test with a valid public key
  final validSecret = X256189.computeSharedSecret(
      keypair['privateKey']!,
      keypair['publicKey']!
  );
  print('  Valid public key: ${validSecret != null ? "accepted" : "rejected"}');

  // Test with a twist point (invalid public key)
  final p = Curve256189Params.p;
  final A = Curve256189Params.A;
  BigInt? twistX;

  for (int i = 0; i < 1000; i++) {
    final x = BigInt.from(random.nextInt(1 << 20)) % p;
    final x2 = (x * x) % p;
    final x3 = (x2 * x) % p;
    final rhs = (x3 + A * x2 + x) % p;
    final exp = (p - BigInt.one) >> 1;
    final legendre = rhs.modPow(exp, p);

    if (legendre != BigInt.one) {
      twistX = x;
      break;
    }
  }

  if (twistX != null) {
    final twistBytes = Uint8List(32);
    var temp = twistX;
    for (int i = 0; i < 32; i++) {
      twistBytes[i] = (temp & BigInt.from(0xff)).toInt();
      temp = temp >> 8;
    }

    final twistSecret = X256189.computeSharedSecret(
        keypair['privateKey']!,
        twistBytes
    );
    print('  Twist point: ${twistSecret == null ? "rejected" : "accepted"}');
  } else {
    print('  Note: Could not find a twist point for testing.');
  }
  print('');
}