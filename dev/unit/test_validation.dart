// test_validation.dart

import 'package:curve256189/curve256189.dart';

int _passed = 0;
int _failed = 0;

void _check(String name, bool result) {
  print('  ${result ? "PASS" : "FAIL"}: $name');
  if (result) {
    _passed++;
  } else {
    _failed++;
  }
}

void main() {
  print('=== Test: Point Validation Curve256189 ===');
  print('');

  final p = Curve256189Params.p;

  print('Test 1 - Base point:');
  _check('G is valid', Montgomery.isValidPoint(MontgomeryPoint.G));
  _check('G is in the prime-order subgroup',
      Montgomery.isInPrimeOrderSubgroup(MontgomeryPoint.G));

  print('');
  print('Test 2 - Infinity:');
  _check('infinity is invalid',
      !Montgomery.isValidPoint(MontgomeryPoint.infinity()));

  print('');
  print('Test 3 - Low-order points:');
  _check('order-2 point (0, 0) is invalid',
      !Montgomery.isValidPoint(MontgomeryPoint(BigInt.zero, BigInt.zero)));
  final x4 = p - BigInt.one;
  final y4 = Montgomery.yFromX(x4)!;
  _check('order-4 point (p-1, y) is invalid',
      !Montgomery.isValidPoint(MontgomeryPoint(x4, y4)));
  _check('order-4 point is not in the prime-order subgroup',
      !Montgomery.isInPrimeOrderSubgroup(MontgomeryPoint(x4, y4)));

  print('');
  print('Test 4 - Mixed-order point:');
  final mixed = Montgomery.add(
    MontgomeryPoint.G,
    MontgomeryPoint(BigInt.zero, BigInt.zero),
  );
  _check('G + (0,0) is on the curve',
      Montgomery.isOnCurve(mixed) && mixed.x != BigInt.zero);
  _check('mixed-order point is not in the prime-order subgroup',
      !Montgomery.isInPrimeOrderSubgroup(mixed));
  _check('mixed-order x is not a valid public key',
      !Montgomery.isValidPublicKeyX(mixed.x));

  print('');
  print('Test 5 - Ordinary points:');
  final twoG = Montgomery.scalarMulFull(BigInt.two, MontgomeryPoint.G);
  _check('2G is valid', Montgomery.isValidPoint(twoG));
  _check('2G is in the prime-order subgroup',
      Montgomery.isInPrimeOrderSubgroup(twoG));

  print('');
  print('Test 6 - Out-of-range coordinates:');
  _check('x = p is invalid',
      !Montgomery.isValidPoint(MontgomeryPoint(p, BigInt.one)));
  _check('negative x is invalid',
      !Montgomery.isValidPoint(MontgomeryPoint(-BigInt.one, BigInt.one)));
  _check('x = 0 is not a valid public key',
      !Montgomery.isValidPublicKeyX(BigInt.zero));

  print('');
  print('=== Results: $_passed passed, $_failed failed ===');
}
