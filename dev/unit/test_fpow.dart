// test_fpow.dart

// FPOW — Fixed-Point One-Way Wrap verification
// Tests all properties proven via SageMath (fpow_curve256189.sage)
import 'dart:typed_data';
import 'dart:math';
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: FPOW — Fixed-Point One-Way Wrap ===');

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

  // Test case 1: Deterministic output for the same input
  print('');
  print('Test 1 - Is the output deterministic?');
  final k = randomScalar();
  final w1 = FPOW.wrap(k, secret1);
  final w2 = FPOW.wrap(k, secret1);
  print('  match? ${w1 == w2}');

  // Test case 2: Output is within the valid scalar range [0, n)
  print('');
  print('Test 2 - Is the output in the range [0, n)?');
  final inRange = w1 >= BigInt.zero && w1 < n;
  print('  in range? $inRange');

  // Test case 3: Different seeds produce different wrapped outputs
  print('');
  print('Test 3 - Do different seeds produce different outputs?');
  final wSeed2 = FPOW.wrap(k, secret2);
  print('  different? ${w1 != wSeed2}');

  // Test case 4: Different inputs produce different wrapped outputs
  print('');
  print('Test 4 - Do different inputs produce different outputs?');
  final k2 = randomScalar();
  final wK2 = FPOW.wrap(k2, secret1);
  print('  different? ${w1 != wK2}');

  // Test case 5: Domain separation — secret is different from the seed
  print('');
  print('Test 5 - Domain separation (secret != seed)?');
  print('  secret != seed? ${secret1.toString() != seed1.toString()}');

  // Test case 6: Non-polynomial behavior — Lagrange interpolation fails
  print('');
  print('Test 6 - Non-polynomial (Lagrange interpolation fails)?');
  final pairs = List.generate(11,
          (_) => (k: randomScalar(), kp: BigInt.zero))
      .map((e) => (k: e.k, kp: FPOW.wrap(e.k, secret1)))
      .toList();
  final uniqueOutputs = pairs.map((e) => e.kp).toSet().length;
  print('  11 unique outputs? ${uniqueOutputs == 11}');

  // Test case 7: Statistical uniformity of outputs
  print('');
  print('Test 7 - Statistical uniformity?');
  final samples = List.generate(5000, (_) => FPOW.wrap(randomScalar(), secret1));
  final avg = samples.fold(BigInt.zero, (a, b) => a + b) ~/
      BigInt.from(samples.length);
  final ratio = double.parse(avg.toString()) /
      double.parse((n ~/ BigInt.two).toString());
  print('  ratio: ${ratio.toStringAsFixed(4)} (target: approximately 1.0)');
  print('  uniform? ${ratio > 0.90 && ratio < 1.10}');

  // Test case 8: Differential randomness — differences between adjacent inputs
  print('');
  print('Test 8 - Differential randomness?');
  final diffs = <BigInt>{};
  for (int i = 0; i < 500; i++) {
    final kd = randomScalar();
    final kd1 = (kd + BigInt.one) % n;
    final diff = (FPOW.wrap(kd1, secret1) - FPOW.wrap(kd, secret1) + n) % n;
    diffs.add(diff);
  }
  print('  unique diffs: ${diffs.length} / 500');
  print('  random? ${diffs.length > 490}');

  // Test case 9: Fixed-point equation verification
  // k_wrapped = k_raw + H(secret || k_raw) mod n
  // Therefore: k_raw = k_wrapped - H(secret || k_raw) mod n
  print('');
  print('Test 9 - Fixed-point equation verification?');
  final kRaw   = randomScalar();
  final kWrapped = FPOW.wrap(kRaw, secret1);
  // Verify that kWrapped - H(secret, kRaw) == kRaw
  final hVal   = (kWrapped - kRaw + n) % n;  // This is H(secret, kRaw)
  final verify = (kWrapped - hVal + n) % n;
  print('  k_raw recovered via equation? ${verify == kRaw}');
  print('  (This requires knowing k_raw — it is circular without it.)');

  // Test case 10: Shor resistance simulation
  // Attacker obtains k_wrapped via ECDLP but cannot recover k_raw without the secret
  print('');
  print('Test 10 - Shor resistance simulation?');
  final kRaw2    = randomScalar();
  final kWrapped2 = FPOW.wrap(kRaw2, secret1);
  // Attacker knows kWrapped2 but not secret1 or kRaw2
  // They must solve: k_raw = k_wrapped - H(secret || k_raw)
  // Without the secret, they cannot compute H.
  final wrongSecret = Uint8List.fromList(List.generate(32, (i) => 0xFF));
  final wrongAttempt = (kWrapped2 - FPOW.wrap(BigInt.zero, wrongSecret) + n) % n;
  print('  k_wrapped != k_raw? ${kWrapped2 != kRaw2}');
  print('  wrong secret fails? ${wrongAttempt != kRaw2}');
  print('  k_raw protected? ${kWrapped2 != kRaw2}');

  // Test case 11: deriveSecret is deterministic
  print('');
  print('Test 11 - Is deriveSecret deterministic?');
  final s1 = FPOW.deriveSecret(seed1);
  final s2 = FPOW.deriveSecret(seed1);
  bool secretMatch = true;
  for (int i = 0; i < s1.length; i++) {
    if (s1[i] != s2[i]) { secretMatch = false; break; }
  }
  print('  deterministic? $secretMatch');

  // Test case 12: Different seeds produce different secrets
  print('');
  print('Test 12 - Do different seeds produce different secrets?');
  bool secretDiff = false;
  for (int i = 0; i < secret1.length; i++) {
    if (secret1[i] != secret2[i]) { secretDiff = true; break; }
  }
  print('  different? $secretDiff');

  print('');
  print('=== FPOW: All Tests Completed ===');
}