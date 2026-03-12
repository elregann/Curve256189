// test_validation.dart
import 'montgomery.dart';
import 'params.dart';
import 'field.dart';

void main() {
  print('=== Test Point Validation Curve256189 ===');

  final p = Curve256189Params.p;
  final A = Curve256189Params.A;

  // Test 1: G valid?
  print('\nTest 1 - Base point G valid?');
  print('  ${Montgomery.isValidPoint(MontgomeryPoint.G)}');

  // Test 2: infinity invalid?
  print('\nTest 2 - Infinity invalid?');
  print('  ${!Montgomery.isValidPoint(MontgomeryPoint.infinity())}');

  // Test 3: order 2 point invalid?
  print('\nTest 3 - Order 2 point (0,0) invalid?');
  print('  ${!Montgomery.isValidPoint(MontgomeryPoint(BigInt.zero, BigInt.zero))}');

  // Test 4: order 4 point invalid?
  // x = p-1, recover y
  print('\nTest 4 - Order 4 point (p-1, y) invalid?');
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

  // Test 5: 2G valid?
  print('\nTest 5 - 2G valid?');
  final twoG = Montgomery.scalarMul(BigInt.two, MontgomeryPoint.G);
  print('  ${Montgomery.isValidPoint(twoG)}');

  // Test 6: out of range invalid?
  print('\nTest 6 - x >= p invalid?');
  print('  ${!Montgomery.isValidPoint(MontgomeryPoint(p, BigInt.one))}');
}