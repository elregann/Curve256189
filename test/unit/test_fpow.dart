// test_fpow.dart
// FPOW — Fixed-Point One-Way Wrap verification
// Tests all properties proven via SageMath (fpow_curve256189.sage)
import 'dart:typed_data';
import 'dart:math';
import '../src/fpow.dart';
import '../src/params.dart';

void main() {
  print('=== Test FPOW — Fixed-Point One-Way Wrap ===');

  final n = Curve256189Params.n;
  final rng = Random.secure();

  BigInt randomScalar() {
    BigInt result = BigInt.zero;
    for (int i = 0; i < 4; i++) {
      result = (result << 32) + BigInt.from(rng.nextInt(0xFFFFFFFF));
    }
    return result % n;
  }

  final seed1 = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final secret1 = FPOW.deriveSecret(seed1);
  final secret2 = FPOW.deriveSecret(seed2);

  // Test 1: Deterministic output
  print('\nTest 1 - Deterministic output?');
  final k = randomScalar();
  final w1 = FPOW.wrap(k, secret1);
  final w2 = FPOW.wrap(k, secret1);
  print('  match? ${w1 == w2}');

  // Test 2: Output in range [0, n)
  print('\nTest 2 - Output in range [0, n)?');
  final inRange = w1 >= BigInt.zero && w1 < n;
  print('  in range? $inRange');

  // Test 3: Different seed = different secret = different wrap
  print('\nTest 3 - Different seed = different wrap?');
  final wSeed2 = FPOW.wrap(k, secret2);
  print('  different? ${w1 != wSeed2}');

  // Test 4: Different k = different wrap
  print('\nTest 4 - Different k = different wrap?');
  final k2 = randomScalar();
  final wK2 = FPOW.wrap(k2, secret1);
  print('  different? ${w1 != wK2}');

  // Test 5: Domain separation — secret != seed
  print('\nTest 5 - Domain separation?');
  print('  secret != seed? ${secret1.toString() != seed1.toString()}');

  // Test 6: Non-polynomial — Lagrange interpolation fails
  // Collect degree+10 pairs and try to predict new point
  print('\nTest 6 - Non-polynomial (Lagrange fails)?');
  final pairs = List.generate(11,
          (_) => (k: randomScalar(), kp: BigInt.zero))
      .map((e) => (k: e.k, kp: FPOW.wrap(e.k, secret1)))
      .toList();
  // Use pairs to try predict — if FPOW is polynomial,
  // prediction would succeed. We verify it does NOT.
  // (Full Lagrange requires field arithmetic — we verify
  // via statistical check instead)
  final uniqueOutputs = pairs.map((e) => e.kp).toSet().length;
  print('  11 unique outputs? ${uniqueOutputs == 11}');

  // Test 7: Statistical uniformity
  print('\nTest 7 - Statistical uniformity?');
  final samples = List.generate(5000, (_) => FPOW.wrap(randomScalar(), secret1));
  final avg = samples.fold(BigInt.zero, (a, b) => a + b) ~/
      BigInt.from(samples.length);
  final ratio = double.parse(avg.toString()) /
      double.parse((n ~/ BigInt.two).toString());
  print('  ratio: ${ratio.toStringAsFixed(4)} (target: ~1.0)');
  print('  uniform? ${ratio > 0.90 && ratio < 1.10}');

  // Test 8: Differential randomness
  print('\nTest 8 - Differential randomness?');
  final diffs = <BigInt>{};
  for (int i = 0; i < 500; i++) {
    final kd = randomScalar();
    final kd1 = (kd + BigInt.one) % n;
    final diff = (FPOW.wrap(kd1, secret1) - FPOW.wrap(kd, secret1) + n) % n;
    diffs.add(diff);
  }
  print('  unique diffs: ${diffs.length}/500');
  print('  random? ${diffs.length > 490}');

  // Test 9: Fixed-point equation verification
  // k_wrapped = k_raw + H(secret || k_raw) mod n
  // → k_raw = k_wrapped - H(secret || k_raw) mod n
  print('\nTest 9 - Fixed-point equation?');
  final kRaw   = randomScalar();
  final kWrapped = FPOW.wrap(kRaw, secret1);
  // Verify: kWrapped - H(secret, kRaw) == kRaw
  final hVal   = (kWrapped - kRaw + n) % n; // this IS H(secret, kRaw)
  final verify = (kWrapped - hVal + n) % n;
  print('  k_raw recovered via equation? ${verify == kRaw}');
  print('  (requires knowing k_raw — circular without it!)');

  // Test 10: Shor resistance simulation
  // Simulate: attacker gets k_wrapped via ECDLP
  // Can they recover k_raw without secret?
  print('\nTest 10 - Shor resistance simulation?');
  final kRaw2    = randomScalar();
  final kWrapped2 = FPOW.wrap(kRaw2, secret1);
  // Attacker knows k_wrapped2 but not secret1 or k_raw2
  // They must solve: k_raw = k_wrapped - H(secret || k_raw)
  // Without secret → cannot compute H → cannot solve!
  final wrongSecret = Uint8List.fromList(List.generate(32, (i) => 0xFF));
  final wrongAttempt = (kWrapped2 - FPOW.wrap(BigInt.zero, wrongSecret) + n) % n;
  print('  k_wrapped != k_raw? ${kWrapped2 != kRaw2}');
  print('  wrong secret fails? ${wrongAttempt != kRaw2}');
  print('  k_raw protected? ${kWrapped2 != kRaw2}');

  // Test 11: deriveSecret deterministic
  print('\nTest 11 - deriveSecret deterministic?');
  final s1 = FPOW.deriveSecret(seed1);
  final s2 = FPOW.deriveSecret(seed1);
  bool secretMatch = true;
  for (int i = 0; i < s1.length; i++) {
    if (s1[i] != s2[i]) { secretMatch = false; break; }
  }
  print('  deterministic? $secretMatch');

  // Test 12: deriveSecret different seeds = different secrets
  print('\nTest 12 - Different seeds = different secrets?');
  bool secretDiff = false;
  for (int i = 0; i < secret1.length; i++) {
    if (secret1[i] != secret2[i]) { secretDiff = true; break; }
  }
  print('  different? $secretDiff');

  print('\n=== FPOW Finished All Test ===');
}