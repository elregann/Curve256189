// test_blinding.dart

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
  print('=== Test: Scalar Blinding Curve256189 ===');
  print('');

  final g = MontgomeryPoint.G;
  final k = BigInt.parse('12345678901234567890');

  print('Test 1 - ladderXOnly is unaffected by blinding:');
  final x1 = Montgomery.ladderXOnly(k, g.x);
  final x2 = Montgomery.ladderXOnly(k, g.x);
  final x3 = Montgomery.ladderXOnly(k, g.x);
  print('  run 1 = $x1');
  print('  run 2 = $x2');
  print('  run 3 = $x3');
  _check('all runs agree', x1 == x2 && x2 == x3);
  _check('result is not infinity', x1 != null);

  print('');
  print('Test 2 - Blind scalar construction:');
  final r1 = Montgomery.blindScalar(k, BigInt.from(1));
  final r2 = Montgomery.blindScalar(k, BigInt.from(2));
  _check('different blinders produce different scalars', r1 != r2);

  print('');
  print('Test 3 - n*G under the ladder:');
  final nG = Montgomery.ladderXOnly(Curve256189Params.n, g.x, blind: false);
  _check('n * G is the point at infinity', nG == null);

  print('');
  print('Test 4 - Full-point blinding consistency:');
  final plain = Montgomery.scalarMulFull(k, g);
  final blind = Montgomery.scalarMulFull(k, g, blind: true);
  _check('blinded full-point multiplication matches',
      Montgomery.pointsEqual(plain, blind));
  _check('result is a valid point', Montgomery.isValidPoint(plain));

  print('');
  print('Test 5 - Blinding on low-order points:');
  final order4 = Montgomery.pointFromX(
    Curve256189Params.p - BigInt.one,
    evenY: true,
  )!;
  final plainOrder4 = Montgomery.scalarMulFull(BigInt.from(3), order4);
  final blindOrder4 =
      Montgomery.scalarMulFull(BigInt.from(3), order4, blind: true);
  _check('blinded order-4 multiplication matches',
      Montgomery.pointsEqual(plainOrder4, blindOrder4));

  final mixed = Montgomery.add(g, MontgomeryPoint(BigInt.zero, BigInt.zero));
  final plainMixed = Montgomery.scalarMulFull(k, mixed);
  final blindMixed = Montgomery.scalarMulFull(k, mixed, blind: true);
  _check('blinded mixed-order multiplication matches',
      Montgomery.pointsEqual(plainMixed, blindMixed));

  print('');
  print('=== Results: $_passed passed, $_failed failed ===');
}
