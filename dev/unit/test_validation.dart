// test_validation.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Point Validation Curve256189 ===');

  final p = Curve256189Params.p;
  final A = Curve256189Params.A;

  // Test case 1: Base point G should be valid
  print('');
  print('Test 1 - Is the base point G valid?');
  print('  ${Montgomery.isValidPoint(MontgomeryPoint.G)}');

  // Test case 2: Point at infinity should be invalid
  print('');
  print('Test 2 - Is the point at infinity invalid?');
  print('  ${!Montgomery.isValidPoint(MontgomeryPoint.infinity())}');

  // Test case 3: Order-2 point (0, 0) should be invalid
  print('');
  print('Test 3 - Is the order-2 point (0, 0) invalid?');
  print('  ${!Montgomery.isValidPoint(MontgomeryPoint(BigInt.zero, BigInt.zero))}');

  // Test case 4: Order-4 point (p-1, y) should be invalid
  // Compute x = p - 1, then recover y from the curve equation
  print('');
  print('Test 4 - Is the order-4 point (p-1, y) invalid?');
  final x4 = p - BigInt.one;
  final x2 = FieldElement.mul(x4, x4);
  final x3 = FieldElement.mul(x4, x2);
  final rhs = FieldElement.add(
    FieldElement.add(x3, FieldElement.mul(A, x2)),
    x4,
  );
  final exp = (p + BigInt.one) >> 2;
  final y4 = FieldElement.pow(rhs, exp);
  final order4Point = MontgomeryPoint(x4, y4);
  print('  on curve? ${Montgomery.isOnCurve(order4Point)}');
  print('  isValidPoint? ${!Montgomery.isValidPoint(order4Point)}');

  // Test case 5: 2G should be valid
  print('');
  print('Test 5 - Is 2G valid?');
  final twoG = Montgomery.scalarMul(BigInt.two, MontgomeryPoint.G);
  print('  ${Montgomery.isValidPoint(twoG)}');

  // Test case 6: Points with x >= p should be invalid
  print('');
  print('Test 6 - Is a point with x >= p invalid?');
  print('  ${!Montgomery.isValidPoint(MontgomeryPoint(p, BigInt.one))}');
}