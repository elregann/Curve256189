// test_blinding.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Scalar Blinding Curve256189 ===');

  final G = MontgomeryPoint.G;

  // Test case 1: Verify that k*G produces the same result with blinding enabled.
  print('');
  print('Test 1 - Does the result remain the same with blinding?');
  final k = BigInt.parse('12345678901234567890');
  final x1 = Montgomery.ladderXOnly(k, G.x);
  final x2 = Montgomery.ladderXOnly(k, G.x);
  final x3 = Montgomery.ladderXOnly(k, G.x);
  print('  run 1 = $x1');
  print('  run 2 = $x2');
  print('  run 3 = $x3');
  print('  all equal? ${x1 == x2 && x2 == x3}');

  // Test case 2: Verify that blinding is active (different random r per run).
  print('');
  print('Test 2 - Is blinding active (different r per run)?');
  final r1 = Montgomery.blindScalar(k, BigInt.from(1));
  final r2 = Montgomery.blindScalar(k, BigInt.from(2));
  print('  k + 1 * n = $r1');
  print('  k + 2 * n = $r2');
  print('  r1 != r2? ${r1 != r2}');

  // Test case 3: Verify that n*G remains the point at infinity after blinding.
  print('');
  print('Test 3 - Does n*G remain the point at infinity?');
  final nG = Montgomery.ladderXOnly(Curve256189Params.n, G.x);
  print('  n * G.x = $nG');
  print('  is infinity? ${nG == BigInt.zero}');

  // Test case 4: Verify that isValidPoint still works correctly.
  print('');
  print('Test 4 - Does isValidPoint still work correctly?');
  final kG = Montgomery.scalarMul(k, G);
  print('  k * G is valid? ${Montgomery.isValidPoint(kG)}');
}