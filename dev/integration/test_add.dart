// test_add.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Edwards add() Consistency ===');

  final G = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);

  // Test case 1: Verify that G + G via add() equals 2G via scalar multiplication.
  final addResult = TwistedEdwards.add(G, G);
  final mulResult = TwistedEdwards.scalarMul(BigInt.two, G);

  print('Test 1 - Does G + G equal 2G?');
  print('  add().x  = ${addResult.x}');
  print('  mul().x  = ${mulResult.x}');
  print('  x equal?  = ${addResult.x == mulResult.x}');
  print('  y equal?  = ${addResult.y == mulResult.y}');

  // Test case 2: Check whether the result of add() lies on the curve.
  print('Test 2 - Is G + G on the curve?');
  print('  isOnCurve: ${TwistedEdwards.isOnCurve(addResult)}');

  // Test case 3: Verify that Montgomery x-coordinates from add() and scalarMul() are consistent.
  final addMontX = TwistedEdwards.toMontgomery(addResult).x;
  final mulMontX = TwistedEdwards.toMontgomery(mulResult).x;
  print('Test 3 - Are Montgomery x coordinates equal?');
  print('  add mont.x = $addMontX');
  print('  mul mont.x = $mulMontX');
  print('  equal? ${addMontX == mulMontX}');
}