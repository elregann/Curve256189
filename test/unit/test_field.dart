import '../src/field.dart';
import '../src/params.dart';

void main() {
  print('=== Test Field Operations ===\n');

  final p = Curve256189Params.p;
  final a = BigInt.parse('123456789012345678901234567890');
  final b = BigInt.parse('987654321098765432109876543210');

  // Test add
  final resultAdd = FieldElement.add(a, b);
  print('Test Add:');
  print('  a + b = $resultAdd');
  print('  Valid? ${resultAdd < p}\n');

  // Test sub
  final resultSub = FieldElement.sub(a, b);
  print('Test Sub:');
  print('  a - b = $resultSub');
  print('  Valid (no negative)? ${resultSub >= BigInt.zero && resultSub < p}\n');

  // Test mul
  final resultMul = FieldElement.mul(a, b);
  print('Test Mul:');
  print('  a * b mod p = $resultMul');
  print('  Valid? ${resultMul < p}\n');

  // Test inv
  final resultInv = FieldElement.inv(a);
  print('Test Inv:');
  print('  inv(a) = $resultInv');
  print('  a * inv(a) mod p == 1? ${FieldElement.mul(a, resultInv) == BigInt.one}\n');

  // Test pow
  final resultPow = FieldElement.pow(a, BigInt.from(3));
  print('Test Pow:');
  print('  a^3 mod p = $resultPow');
  print('  Valid? ${resultPow < p}\n');

  print('=== Semua Test Selesai ===');
}