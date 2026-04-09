// test_field.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Field Operations ===');
  print('');

  final p = Curve256189Params.p;
  final a = BigInt.parse('123456789012345678901234567890');
  final b = BigInt.parse('987654321098765432109876543210');

  // Test case 1: Field addition
  final resultAdd = FieldElement.add(a, b);
  print('Test 1 - Addition:');
  print('  a + b = $resultAdd');
  print('  Valid? ${resultAdd < p}');
  print('');

  // Test case 2: Field subtraction
  final resultSub = FieldElement.sub(a, b);
  print('Test 2 - Subtraction:');
  print('  a - b = $resultSub');
  print('  Valid (no negative)? ${resultSub >= BigInt.zero && resultSub < p}');
  print('');

  // Test case 3: Field multiplication
  final resultMul = FieldElement.mul(a, b);
  print('Test 3 - Multiplication:');
  print('  a * b mod p = $resultMul');
  print('  Valid? ${resultMul < p}');
  print('');

  // Test case 4: Modular inverse
  final resultInv = FieldElement.inv(a);
  print('Test 4 - Modular Inverse:');
  print('  inv(a) = $resultInv');
  print('  a * inv(a) mod p == 1? ${FieldElement.mul(a, resultInv) == BigInt.one}');
  print('');

  // Test case 5: Modular exponentiation
  final resultPow = FieldElement.pow(a, BigInt.from(3));
  print('Test 5 - Exponentiation:');
  print('  a^3 mod p = $resultPow');
  print('  Valid? ${resultPow < p}');
  print('');

  print('=== All Tests Completed ===');
}