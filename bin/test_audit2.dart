import 'dart:math';
import 'dart:typed_data';
import 'src/eddsa.dart';
import 'src/edwards.dart';
import 'src/hfe.dart';

class Curve256189Test {

  static final rand = Random.secure();

  static Uint8List randomBytes(int len) {
    final b = Uint8List(len);
    for (int i = 0; i < len; i++) {
      b[i] = rand.nextInt(256);
    }
    return b;
  }

  static BigInt randomScalar() {
    return BigInt.from(rand.nextInt(1 << 30));
  }

  static bool pointEqual(EdwardsPoint p1, EdwardsPoint p2) {
    return p1.x == p2.x && p1.y == p2.y;
  }

  // =========================
  // 1. GROUP LAW TEST
  // =========================

  static void testGroupLaw() {

    print("Running group law test...");

    for (int i = 0; i < 50000; i++) {

      final k1 = randomScalar();
      final k2 = randomScalar();

      final p1 = TwistedEdwards.scalarMul(k1, EdDSA.G);
      final p2 = TwistedEdwards.scalarMul(k2, EdDSA.G);

      final left = TwistedEdwards.scalarMul(k1 + k2, EdDSA.G);
      final right = TwistedEdwards.add(p1, p2);

      if (!pointEqual(left, right)) {

        print("❌ Group law failed at iteration $i");
        return;

      }

    }

    print("✅ Group law OK");

  }

  // =========================
  // 2. SCALAR CONSISTENCY
  // =========================

  static void testScalarConsistency() {

    print("Running scalar consistency test...");

    for (int i = 0; i < 50000; i++) {

      final k = randomScalar();

      final p1 = TwistedEdwards.scalarMul(k, EdDSA.G);

      final half = k ~/ BigInt.two;

      final p2 = TwistedEdwards.scalarMul(half, EdDSA.G);

      final p3 = TwistedEdwards.add(p2, p2);

      if (!pointEqual(p1, p3) && k.isEven) {

        print("❌ Scalar multiplication inconsistency");
        return;

      }

    }

    print("✅ Scalar multiplication OK");

  }

  // =========================
  // 3. SIGNATURE TEST
  // =========================

  static void testSignVerify() {

    print("Running signature test...");

    for (int i = 0; i < 10000; i++) {

      final seed = randomBytes(32);

      final keypair = EdDSA.generateKeyPair(seed);

      final msg = randomBytes(32);

      final sig = EdDSA.sign(
        msg,
        keypair['privateKey']!,
      );

      final ok = EdDSA.verify(
        msg,
        sig,
        keypair['publicKey']!,
      );

      if (!ok) {

        print("❌ Signature verification failed");
        return;

      }

    }

    print("✅ Signature test OK");

  }

  // =========================
  // 4. FORGERY TEST
  // =========================

  static void testForgery() {

    print("Running forgery test...");

    final seed = randomBytes(32);

    final keypair = EdDSA.generateKeyPair(seed);

    final pk = keypair['publicKey']!;

    final msg = randomBytes(32);

    for (int i = 0; i < 100000; i++) {

      final fakeSig = randomBytes(65);

      final ok = EdDSA.verify(msg, fakeSig, pk);

      if (ok) {

        print("🚨 Forged signature detected!");
        return;

      }

    }

    print("✅ No forgery detected");

  }

  // =========================
  // 5. HFE COLLISION TEST
  // =========================

  static void testHFECollision() {

    print("Running HFE collision test...");

    final seen = <BigInt>{};

    for (int i = 0; i < 100000; i++) {

      final k = randomScalar();

      final seed = randomBytes(32);

      final constants = HFE.deriveConstants(seed);

      final wrapped = HFE.wrap(
        k,
        constants['a']!,
        constants['b']!,
        constants['c']!,
        constants['d']!,
        constants['coeff']!,
      );

      if (seen.contains(wrapped)) {

        print("⚠ HFE collision detected!");
        return;

      }

      seen.add(wrapped);

    }

    print("✅ No HFE collisions detected");

  }

  // =========================
  // RUN ALL TESTS
  // =========================

  static void runAll() {

    print("================================");
    print(" Curve256189 Test Suite");
    print("================================");

    testGroupLaw();
    testScalarConsistency();
    testSignVerify();
    testForgery();
    testHFECollision();

    print("================================");
    print(" All tests finished");
    print("================================");

  }

}

void main() {
  Curve256189Test.runAll();
}