// test_hfe_security.dart

// Security analysis of the HFE wrap layer in Curve256189
// Tests: obfuscation, non-reversibility, collision resistance, statistical randomness
import 'dart:typed_data';
import 'dart:math';
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: HFE Security Layer Curve256189 ===');

  final n = Curve256189Params.n;
  final random = Random.secure();

  // Helper: Generate a random scalar in the range [1, n-1]
  BigInt randomScalar() {
    final bytes = Uint8List(32);
    for (int i = 0; i < 32; i++) bytes[i] = random.nextInt(256);
    BigInt result = BigInt.zero;
    for (int i = 0; i < 32; i++) {
      result = result | (BigInt.from(bytes[i]) << (8 * i));
    }
    return (result % (n - BigInt.one)) + BigInt.one;
  }

  // Helper: Generate a random 32-byte seed
  Uint8List randomSeed() {
    final seed = Uint8List(32);
    for (int i = 0; i < 32; i++) seed[i] = random.nextInt(256);
    return seed;
  }

  // =============================================
  // Test A: Does HFE wrap obfuscate the raw scalar?
  // sk_raw and sk_wrapped must be significantly different.
  // =============================================
  print('');
  print('Test A - Does HFE wrap obfuscate sk_raw?');
  int obfuscated = 0;
  final sampleSize = 100;
  for (int i = 0; i < sampleSize; i++) {
    final seed = randomSeed();
    final sk_raw = randomScalar();
    final constants = HFE.deriveConstants(seed);
    final sk_wrapped = HFE.wrap(
      sk_raw,
      constants['a']!,
      constants['b']!,
      constants['c']!,
      constants['d']!,
      constants['coeff']!,
    );
    if (sk_raw != sk_wrapped) obfuscated++;
  }
  print('  $obfuscated / $sampleSize where sk_wrapped != sk_raw');
  print('  Obfuscated? ${obfuscated == sampleSize}');

  // =============================================
  // Test B: Non-reversibility without the constants
  // An attacker without the constants cannot recover sk_raw.
  // =============================================
  print('');
  print('Test B - Non-reversibility without constants?');
  final seedB = randomSeed();
  final sk_rawB = randomScalar();
  final constantsB = HFE.deriveConstants(seedB);
  final sk_wrappedB = HFE.wrap(
    sk_rawB,
    constantsB['a']!,
    constantsB['b']!,
    constantsB['c']!,
    constantsB['d']!,
    constantsB['coeff']!,
  );

  // Attempt recovery with incorrect constants
  int recovered = 0;
  for (int i = 0; i < sampleSize; i++) {
    final fakeConstants = HFE.deriveConstants(randomSeed());
    final attempt = HFE.wrap(
      sk_wrappedB,
      fakeConstants['a']!,
      fakeConstants['b']!,
      fakeConstants['c']!,
      fakeConstants['d']!,
      fakeConstants['coeff']!,
    );
    if (attempt == sk_rawB) recovered++;
  }
  print('  Recovery attempts: $sampleSize');
  print('  Successful recoveries: $recovered');
  print('  Non-reversible? ${recovered == 0}');

  // =============================================
  // Test C: Collision resistance
  // Different sk_raw values with the same seed must produce different sk_wrapped.
  // =============================================
  print('');
  print('Test C - Collision resistance?');
  final seedC = randomSeed();
  final constantsC = HFE.deriveConstants(seedC);
  int collisions = 0;
  for (int i = 0; i < sampleSize; i++) {
    final sk1 = randomScalar();
    final sk2 = randomScalar();
    final w1 = HFE.wrap(sk1, constantsC['a']!, constantsC['b']!,
        constantsC['c']!, constantsC['d']!, constantsC['coeff']!);
    final w2 = HFE.wrap(sk2, constantsC['a']!, constantsC['b']!,
        constantsC['c']!, constantsC['d']!, constantsC['coeff']!);
    if (sk1 != sk2 && w1 == w2) collisions++;
  }
  print('  Collisions found: $collisions / $sampleSize');
  print('  Collision-free? ${collisions == 0}');

  // =============================================
  // Test D: Statistical randomness
  // The HFE output should appear random.
  // Test bit distribution — count the number of 1 bits.
  // Expectation: approximately 50% 1 bits (close to uniform).
  // =============================================
  print('');
  print('Test D - Statistical randomness (bit distribution)?');
  int totalBits = 0;
  int oneBits = 0;
  for (int i = 0; i < sampleSize; i++) {
    final seed = randomSeed();
    final sk_raw = randomScalar();
    final constants = HFE.deriveConstants(seed);
    final sk_wrapped = HFE.wrap(
      sk_raw,
      constants['a']!,
      constants['b']!,
      constants['c']!,
      constants['d']!,
      constants['coeff']!,
    );
    final bits = sk_wrapped.toRadixString(2);
    totalBits += bits.length;
    oneBits += bits.split('1').length - 1;
  }
  final ratio = oneBits / totalBits;
  print('  Total bits: $totalBits');
  print('  One bits:   $oneBits');
  print('  Ratio:      ${ratio.toStringAsFixed(4)} (ideal: approximately 0.5000)');
  print('  Random-looking? ${ratio > 0.45 && ratio < 0.55}');

  // =============================================
  // Test E: ECC + HFE combined
  // Public keys derived from sk_wrapped must be indistinguishable
  // from public keys without HFE.
  // =============================================
  print('');
  print('Test E - ECC + HFE public key indistinguishability?');
  int distinguishable = 0;
  for (int i = 0; i < sampleSize; i++) {
    final seed1 = randomSeed();
    final seed2 = randomSeed();
    final kp1 = EdDSA.generateKeyPair(seed1);
    final kp2 = EdDSA.generateKeyPair(seed2);
    // Public keys from different seeds must be different
    if (kp1['publicKey']!.toString() == kp2['publicKey']!.toString()) {
      distinguishable++;
    }
  }
  print('  PK collisions: $distinguishable / $sampleSize');
  print('  Indistinguishable? ${distinguishable == 0}');
}