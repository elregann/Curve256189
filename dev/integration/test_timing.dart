// test_timing.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Constant-Time Scalar Multiplication ===');
  print('');

  final G_ed = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);
  final n = Curve256189Params.n;

  // Test case 1: Verify that n * G equals the neutral point (0, 1)
  print('Test 1 - Does n * G equal the neutral point (0, 1)?');
  final nG = TwistedEdwards.scalarMul(n, G_ed);
  print('  n * G.x = ${nG.x}');
  print('  n * G.y = ${nG.y}');
  print('  Valid? ${nG.x == BigInt.zero && nG.y == BigInt.one}');
  print('');

  // Test case 2: Verify that 1 * G equals G
  print('Test 2 - Does 1 * G equal G?');
  final oneG = TwistedEdwards.scalarMul(BigInt.one, G_ed);
  print('  Valid? ${oneG.x == G_ed.x && oneG.y == G_ed.y}');
  print('');

  // Test case 3: Verify that 2 * G equals G + G
  print('Test 3 - Does 2 * G equal G + G?');
  final twoG = TwistedEdwards.scalarMul(BigInt.two, G_ed);
  final GplusG = TwistedEdwards.add(G_ed, G_ed);
  print('  Valid? ${twoG.x == GplusG.x && twoG.y == GplusG.y}');
  print('');

  // Test case 4: Timing comparison between scalars with many zero bits and many one bits
  final scalarManyZeros = BigInt.parse(
      '100000000000000000000000000000000000000000000000000000000000000000', radix: 16
  );

  final scalarManyOnes = BigInt.parse(
      '1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', radix: 16
  );

  print('Test 4 - Timing comparison:');

  final sw1 = Stopwatch()..start();
  for (int i = 0; i < 5; i++) {
    TwistedEdwards.scalarMul(scalarManyZeros, G_ed);
  }
  sw1.stop();
  final timeZeros = sw1.elapsedMilliseconds;

  final sw2 = Stopwatch()..start();
  for (int i = 0; i < 5; i++) {
    TwistedEdwards.scalarMul(scalarManyOnes, G_ed);
  }
  sw2.stop();
  final timeOnes = sw2.elapsedMilliseconds;

  print('  Time for scalar with many zeros: ${timeZeros} ms (5 iterations)');
  print('  Time for scalar with many ones:  ${timeOnes} ms (5 iterations)');
  print('  Difference: ${(timeZeros - timeOnes).abs()} ms');
  print('  Is timing consistent? ${(timeZeros - timeOnes).abs() < 500}');
  print('');

  // Test case 5: Verify that EdDSA sign and verify still work correctly after Montgomery Ladder changes
  print('Test 5 - Does EdDSA remain valid after Montgomery Ladder implementation?');
  print('  (Run test_eddsa.dart for confirmation.)');
  print('');

  print('=== All Tests Completed ===');
}