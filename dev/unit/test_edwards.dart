// test_edwards.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Twisted Edwards Operations ===');
  print('');

  // Test case 1: Verify Twisted Edwards curve parameters a and d
  print('Test 1 - Twisted Edwards parameters:');
  print('  a = ${TwistedEdwards.a}');
  print('  d = ${TwistedEdwards.d}');
  print('');

  // Test case 2: Convert base point G from Montgomery to Edwards coordinates
  final G_mont = MontgomeryPoint.G;
  final G_ed = TwistedEdwards.fromMontgomery(G_mont);
  print('Test 2 - Convert base point G (Montgomery -> Edwards):');
  print('  G_ed.x = ${G_ed.x}');
  print('  G_ed.y = ${G_ed.y}');
  print('');

  // Test case 3: Verify that the converted G lies on the Edwards curve
  print('Test 3 - Is G (Edwards) on the curve?');
  print('  isOnCurve(G_ed): ${TwistedEdwards.isOnCurve(G_ed)}');
  print('');

  // Test case 4: Verify point addition (G + G == 2G) using Montgomery double as reference
  final G2_ed = TwistedEdwards.add(G_ed, G_ed);
  final G2_mont = TwistedEdwards.fromMontgomery(
    Montgomery.double_(G_mont),
  );
  print('Test 4 - Does G_ed + G_ed equal 2G (from Montgomery)?');
  print('  G_ed + G_ed == 2G? ${G2_ed.x == G2_mont.x && G2_ed.y == G2_mont.y}');
  print('');

  // Test case 5: Verify that n * G equals the neutral point (0, 1)
  final n = Curve256189Params.n;
  final nG_ed = TwistedEdwards.scalarMul(n, G_ed);
  print('Test 5 - Does n * G equal the neutral point (0, 1)?');
  print('  n * G.x = ${nG_ed.x}');
  print('  n * G.y = ${nG_ed.y}');
  print('  n * G == (0, 1)? ${nG_ed.x == BigInt.zero && nG_ed.y == BigInt.one}');
  print('');

  print('=== All Tests Completed ===');
}