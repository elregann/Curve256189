import 'dart:math';
import 'dart:typed_data';

import 'src/eddsa.dart';
import 'src/edwards.dart';

class Curve256189SecurityTest {

  static final rand = Random.secure();

  static Uint8List randomBytes(int len) {
    final b = Uint8List(len);
    for (int i = 0; i < len; i++) {
      b[i] = rand.nextInt(256);
    }
    return b;
  }

  static bool pointEqual(EdwardsPoint a, EdwardsPoint b) {
    return a.x == b.x && a.y == b.y;
  }

  // =========================
  // 1 INVALID POINT TEST
  // =========================

  static void testInvalidPointDecode() {

    print("Running invalid point decode test...");

    for (int i = 0; i < 100000; i++) {

      final bytes = randomBytes(33);

      final P = TwistedEdwards.decodePoint(bytes);

      if (P != null) {

        if (!TwistedEdwards.isOnCurve(P)) {

          print("🚨 Invalid point accepted!");
          return;

        }

      }

    }

    print("✅ Invalid point test OK");
  }

  // =========================
  // 2 SIGNATURE MALLEABILITY
  // =========================

  static void testSignatureMalleability() {

    print("Running signature malleability test...");

    final seed = randomBytes(32);

    final keypair = EdDSA.generateKeyPair(seed);

    final msg = randomBytes(32);

    final sig = EdDSA.sign(msg, keypair['privateKey']!);

    final fake = Uint8List.fromList(sig);

    // flip last byte
    fake[fake.length - 1] ^= 1;

    final ok = EdDSA.verify(msg, fake, keypair['publicKey']!);

    if (ok) {

      print("🚨 Signature malleable!");
      return;

    }

    print("✅ Signature malleability test OK");
  }

  // =========================
  // 3 ENCODE / DECODE TEST
  // =========================

  static void testPointEncoding() {

    print("Running encode/decode test...");

    final G = EdDSA.G;

    for (int i = 0; i < 50000; i++) {

      final k = BigInt.from(rand.nextInt(1 << 30));

      final P = TwistedEdwards.scalarMul(k, G);

      final enc = TwistedEdwards.encodePoint(P);

      final dec = TwistedEdwards.decodePoint(enc);

      if (dec == null || !pointEqual(P, dec)) {

        print("🚨 Encode/decode mismatch!");
        return;

      }

    }

    print("✅ Encode/decode test OK");
  }

  static void runAll() {

    print("================================");
    print(" Curve256189 Security Test");
    print("================================");

    testInvalidPointDecode();
    testSignatureMalleability();
    testPointEncoding();

    print("================================");
    print(" Security tests finished");
    print("================================");
  }

}

void main() {

  Curve256189SecurityTest.runAll();

}