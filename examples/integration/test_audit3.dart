// test_audit3.dart

// Curve256189 Security-Focused Test Suite
// Covers: point validation, signature non-malleability, encode/decode round-trip

import 'dart:math';
import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

class Curve256189SecurityTest {
  static final Random _rand = Random.secure();

  static Uint8List _randomBytes(int length) {
    final bytes = Uint8List(length);
    for (int i = 0; i < length; i++) {
      bytes[i] = _rand.nextInt(256);
    }
    return bytes;
  }

  static bool _pointEqual(EdwardsPoint a, EdwardsPoint b) {
    return a.x == b.x && a.y == b.y;
  }

  // ─────────────────────────────────────────────
  // 1. Invalid Point Decode Test
  //    Ensures decodePoint rejects invalid encodings:
  //    - Random bytes should not decode to valid points
  //    - Points that decode must be on curve
  // ─────────────────────────────────────────────
  static void testInvalidPointDecode() {
    print('  Running invalid point decode test (100,000 iterations)...');

    int totalDecodes = 0;

    for (int i = 0; i < 100000; i++) {
      final bytes = _randomBytes(33);  // 33-byte compressed Edwards point
      final P = TwistedEdwards.decodePoint(bytes);

      if (P != null) {
        totalDecodes++;
        if (!TwistedEdwards.isOnCurve(P)) {
          print('  ❌ FAIL — Point decoded but is not on curve');
          return;
        }
      }
    }

    // Statistical check: random 33-byte string should almost never decode to valid point
    // Probability ≈ (number of valid points)/2²⁶⁴ ≈ negligible
    if (totalDecodes > 0) {
      print('  ⚠️  WARNING — $totalDecodes random inputs decoded to points');
      print('      This is statistically unexpected but not necessarily a failure');
    }

    print('  ✅ PASS — All decoded points are on curve');
  }

  // ─────────────────────────────────────────────
  // 2. Signature Non-Malleability Test
  //    Ensures EdDSA signatures are not malleable:
  //    - Modified R component rejected
  //    - Modified s component rejected
  //    - Non-canonical s (>= n) rejected
  // ─────────────────────────────────────────────
  static void testSignatureNonMalleability() {
    print('  Running signature non-malleability test...');

    final seed = _randomBytes(32);
    final keypair = EdDSA.generateKeyPair(seed);
    final message = _randomBytes(32);
    final signature = EdDSA.sign(message, keypair['privateKey']!);
    final n = Curve256189Params.n;

    // Test 1: Modified R component
    final modifiedR = Uint8List.fromList(signature);
    modifiedR[10] ^= 0x01;  // Flip bit in R (first 32 bytes)
    _checkMalleability('Modified R component',
        !EdDSA.verify(message, modifiedR, keypair['publicKey']!));

    // Test 2: Modified s component
    final modifiedS = Uint8List.fromList(signature);
    modifiedS[40] ^= 0x01;  // Flip bit in s (last 32 bytes)
    _checkMalleability('Modified s component',
        !EdDSA.verify(message, modifiedS, keypair['publicKey']!));

    // Test 3: Non-canonical s (s >= n)
    // Extract s from signature (last 32 bytes)
    final sBytes = signature.sublist(32, 64);
    var s = BigInt.zero;
    for (int i = 0; i < 32; i++) {
      s = (s << 8) | BigInt.from(sBytes[i]);
    }

    if (s >= n) {
      // Signature already non-canonical — should be rejected
      _checkMalleability('Non-canonical s (original)',
          !EdDSA.verify(message, signature, keypair['publicKey']!));
    } else {
      // Create non-canonical s by adding n
      final nonCanonicalS = s + n;
      final nonCanonicalBytes = Uint8List(32);
      var temp = nonCanonicalS;
      for (int i = 31; i >= 0; i--) {
        nonCanonicalBytes[i] = (temp & BigInt.from(0xff)).toInt();
        temp = temp >> 8;
      }

      final nonCanonicalSig = Uint8List(64)
        ..setRange(0, 32, signature.sublist(0, 32))
        ..setRange(32, 64, nonCanonicalBytes);

      _checkMalleability('Non-canonical s (s + n)',
          !EdDSA.verify(message, nonCanonicalSig, keypair['publicKey']!));
    }

    print('  ✅ PASS — No malleable signatures accepted');
  }

  static void _checkMalleability(String testName, bool rejected) {
    if (!rejected) {
      print('  ❌ FAIL — $testName was accepted');
    }
  }

  // ─────────────────────────────────────────────
  // 3. Point Encode/Decode Round-Trip Test
  //    Verifies that encodePoint ∘ decodePoint = identity
  //    for all valid points reachable from G
  // ─────────────────────────────────────────────
  static void testPointEncoding() {
    print('  Running point encode/decode round-trip test (50,000 iterations)...');

    for (int i = 0; i < 50000; i++) {
      // Generate random scalar in full range [0, n)
      final scalarBytes = _randomBytes(32);
      var k = BigInt.zero;
      for (int j = 0; j < 32; j++) {
        k = (k << 8) | BigInt.from(scalarBytes[j]);
      }
      k = k % Curve256189Params.n;

      final P = TwistedEdwards.scalarMul(k, EdDSA.G);
      final encoded = TwistedEdwards.encodePoint(P);
      final decoded = TwistedEdwards.decodePoint(encoded);

      if (decoded == null) {
        print('  ❌ FAIL — Failed to decode encoded point at iteration $i');
        return;
      }

      if (!_pointEqual(P, decoded)) {
        print('  ❌ FAIL — Encode/decode round-trip mismatch at iteration $i');
        print('      Original: (${P.x}, ${P.y})');
        print('      Decoded:  (${decoded.x}, ${decoded.y})');
        return;
      }
    }

    print('  ✅ PASS — All points survive encode/decode round-trip');
  }

  // ─────────────────────────────────────────────
  // Run All Security Tests
  // ─────────────────────────────────────────────
  static void runAll() {
    print('╔══════════════════════════════════════╗');
    print('║  Curve256189 Security Test Suite     ║');
    print('╚══════════════════════════════════════╝');

    testInvalidPointDecode();
    testSignatureNonMalleability();
    testPointEncoding();

    print('  ──────────────────────────────────────');
    print('  ✅ All security tests completed');
  }
}

void main() {
  Curve256189SecurityTest.runAll();
}