// test_montgomery.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Montgomery Operations ===');
  print('');

  // Test case 1: Verify that the base point lies on the curve
  final G = MontgomeryPoint.G;
  print('Test 1 - Does the base point lie on the curve?');
  print('  isOnCurve(G): ${Montgomery.isOnCurve(G)}');
  print('');

  // Test case 2: Point doubling (2G)
  final g2 = Montgomery.double_(G);
  print('Test 2 - Point doubling (2G):');
  print('  2G.x = ${g2.x}');
  print('  2G.y = ${g2.y}');
  print('  isOnCurve(2G): ${Montgomery.isOnCurve(g2)}');
  print('');

  // Test case 3: Point addition (G + G should equal 2G)
  final gplusG = Montgomery.add(G, G);
  print('Test 3 - Point addition (G + G == 2G?):');
  print('  G + G == 2G? ${gplusG.x == g2.x && gplusG.y == g2.y}');
  print('');

  // Test case 4: Scalar multiplication (4G)
  final g4 = Montgomery.scalarMul(BigInt.from(4), G);
  print('Test 4 - Scalar multiplication (4G):');
  print('  4G.x = ${g4.x}');
  print('  4G.y = ${g4.y}');
  print('  isOnCurve(4G): ${Montgomery.isOnCurve(g4)}');
  print('');

  // Test case 5: Verify that n * G equals the point at infinity
  final n = Curve256189Params.n;
  final nG = Montgomery.scalarMul(n, G);
  print('Test 5 - Does n * G equal the point at infinity?');
  print('  n * G isInfinity: ${nG.isInfinity}');
  print('');

  // Test case 6: Verify that infinity + G == G
  final inf = MontgomeryPoint.infinity();
  final infPlusG = Montgomery.add(inf, G);
  print('Test 6 - Does infinity + G equal G?');
  print('  result == G? ${infPlusG.x == G.x && infPlusG.y == G.y}');
  print('');

  // Test case 7: Small Subgroup Attack Prevention
  final lowOrderPoint = MontgomeryPoint(BigInt.zero, BigInt.zero);
  print('Test 7 - Reject low-order point (x=0):');
  print('  isValidPoint(lowOrder): ${Montgomery.isValidPoint(lowOrderPoint)} (Should be false)');
  print('');

  // Test case 8: Blinding Consistency
  final k = BigInt.from(1337);
  final res1 = Montgomery.scalarMul(k, G);
  final res2 = Montgomery.scalarMul(k, G);
  print('Test 8 - Blinding consistency (Same result with different random blinding?):');
  print('  res1 == res2? ${res1.x == res2.x}');
  print('');

  print('=== All Tests Completed ===');
}