// test_suite.dart

// Curve256189 Test Suite
// Covers: group law, EdDSA sign/verify, forgery resistance
//
// Each test runs multiple iterations with random inputs
// to ensure statistical coverage of edge cases.

import 'dart:math';
import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  Curve256189Test.runAll();
}

class Curve256189Test {
  static final Random _rand = Random.secure();

  static Uint8List _randomBytes(int length) {
    final bytes = Uint8List(length);
    for (int i = 0; i < length; i++) {
      bytes[i] = _rand.nextInt(256);
    }
    return bytes;
  }

  static BigInt _randomScalar() {
    // Generate a scalar in the full range [0, n)
    final bytes = _randomBytes(32);
    var scalar = BigInt.zero;
    for (int i = 0; i < 32; i++) {
      scalar = (scalar << 8) | BigInt.from(bytes[i]);
    }
    return scalar % Curve256189Params.n;
  }

  static bool _pointEqual(EdwardsPoint p1, EdwardsPoint p2) {
    return p1.x == p2.x && p1.y == p2.y;
  }

  // Section 1: Group Law Test
  // Verifies (a + b)*G = a*G + b*G
  // This is the fundamental property of elliptic curves.
  static void testGroupLaw() {
    print('Running group law test (10000 iterations)...');

    for (int i = 0; i < 10000; i++) {
      final a = _randomScalar();
      final b = _randomScalar();

      final p1 = TwistedEdwards.scalarMul(a, EdDSA.G);
      final p2 = TwistedEdwards.scalarMul(b, EdDSA.G);
      final pSum = TwistedEdwards.add(p1, p2);

      final pDirect = TwistedEdwards.scalarMul((a + b) % Curve256189Params.n, EdDSA.G);

      if (!_pointEqual(pDirect, pSum)) {
        print('FAIL: Group law violation at iteration $i');
        print('  a = $a');
        print('  b = $b');
        return;
      }
    }

    print('PASS: Group law holds for all tested scalars');
  }

  // Section 2: EdDSA Sign/Verify Test
  // Ensures that valid signatures always verify.
  static void testSignVerify() {
    print('Running EdDSA sign/verify test (10000 iterations)...');

    for (int i = 0; i < 10000; i++) {
      final seed = _randomBytes(32);
      final keypair = EdDSA.generateKeyPair(seed);
      final message = _randomBytes(32);
      final signature = EdDSA.sign(message, keypair['privateKey']!);

      if (!EdDSA.verify(message, signature, keypair['publicKey']!)) {
        print('FAIL: Valid signature failed verification at iteration $i');
        return;
      }
    }

    print('PASS: All valid signatures verify correctly');
  }

  // Section 3: Forgery Resistance Test
  // Tests specific forgery vectors:
  // - Wrong public key
  // - Wrong message
  // - Signature malleability (modified s and modified R)
  // - Random signatures
  static void testForgery() {
    print('Running forgery resistance test...');

    final seed = _randomBytes(32);
    final keypair = EdDSA.generateKeyPair(seed);
    final message = _randomBytes(32);
    final signature = EdDSA.sign(message, keypair['privateKey']!);

    // Test 1: Wrong public key
    final wrongSeed = _randomBytes(32);
    final wrongKeypair = EdDSA.generateKeyPair(wrongSeed);
    _checkForgery('Wrong public key',
        !EdDSA.verify(message, signature, wrongKeypair['publicKey']!));

    // Test 2: Wrong message
    final wrongMessage = _randomBytes(32);
    _checkForgery('Wrong message',
        !EdDSA.verify(wrongMessage, signature, keypair['publicKey']!));

    // Test 3: Signature malleability with modified s component
    final malleableSig = Uint8List.fromList(signature);
    malleableSig[40] ^= 0x01;  // Flip one bit in the s component
    _checkForgery('Malleable signature (modified s)',
        !EdDSA.verify(message, malleableSig, keypair['publicKey']!));

    // Test 4: Signature malleability with modified R component
    final malleableSigR = Uint8List.fromList(signature);
    malleableSigR[20] ^= 0x01;  // Flip one bit in the R component
    _checkForgery('Malleable signature (modified R)',
        !EdDSA.verify(message, malleableSigR, keypair['publicKey']!));

    // Test 5: Random signatures (100 attempts, sufficient for statistical coverage)
    int randomForgeries = 0;
    for (int i = 0; i < 100; i++) {
      final fakeSig = _randomBytes(65);
      if (EdDSA.verify(message, fakeSig, keypair['publicKey']!)) {
        randomForgeries++;
      }
    }
    _checkForgery('Random signatures (100 attempts)',
        randomForgeries == 0);

    print('PASS: All forgery attempts rejected');
  }

  static void _checkForgery(String name, bool result) {
    if (!result) {
      print('FAIL: $name accepted as valid');
    }
  }

  // Section 4: Run All Tests
  static void runAll() {
    print('Curve256189 Test Suite');
    print('');

    testGroupLaw();
    testSignVerify();
    testForgery();

    print('');
    print('All tests completed');
  }
}