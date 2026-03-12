// test_add.dart
import 'edwards.dart';
import 'montgomery.dart';

void main() {
  print('=== Test Edwards add() Consistency ===');

  final G = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);

  // Test 1: G + G via add() == 2G via scalarMul?
  final addResult = TwistedEdwards.add(G, G);
  final mulResult = TwistedEdwards.scalarMul(BigInt.two, G);

  print('Test 1 - G + G == 2G?');
  print('  add().x  = ${addResult.x}');
  print('  mul().x  = ${mulResult.x}');
  print('  x sama?  = ${addResult.x == mulResult.x}');
  print('  y sama?  = ${addResult.y == mulResult.y}');

  // Test 2: add() on curve?
  print('Test 2 - G + G on curve?');
  print('  isOnCurve: ${TwistedEdwards.isOnCurve(addResult)}');

  // Test 3: Montgomery x konsisten?
  final addMontX = TwistedEdwards.toMontgomery(addResult).x;
  final mulMontX = TwistedEdwards.toMontgomery(mulResult).x;
  print('Test 3 - Montgomery x sama?');
  print('  add mont.x = $addMontX');
  print('  mul mont.x = $mulMontX');
  print('  sama? ${addMontX == mulMontX}');
}