// test_montgomery.dart

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

MontgomeryPoint _naiveMul(BigInt k, MontgomeryPoint p) {
  var result = MontgomeryPoint.infinity();
  var addend = p;
  var scalar = k;
  while (scalar > BigInt.zero) {
    if (scalar.isOdd) result = Montgomery.add(result, addend);
    addend = Montgomery.double_(addend);
    scalar >>= 1;
  }
  return result;
}

void main() {
  print('=== Test: Montgomery Operations ===');
  print('');

  final g = MontgomeryPoint.G;
  final n = Curve256189Params.n;

  print('Test 1 - Curve and doubling:');
  _check('G lies on the curve', Montgomery.isOnCurve(g));
  final g2 = Montgomery.double_(g);
  _check('2G lies on the curve', Montgomery.isOnCurve(g2));
  _check('G + G == 2G', Montgomery.pointsEqual(Montgomery.add(g, g), g2));

  print('');
  print('Test 2 - Scalar multiplication:');
  final g4 = Montgomery.scalarMulFull(BigInt.from(4), g);
  _check('4G lies on the curve', Montgomery.isOnCurve(g4));
  _check('4G == 2(2G)', Montgomery.pointsEqual(g4, Montgomery.double_(g2)));

  for (final k in [
    BigInt.one,
    BigInt.two,
    BigInt.from(3),
    BigInt.from(13),
    BigInt.from(255),
    BigInt.from(1024)
  ]) {
    _check(
        'scalarMulFull($k) matches double-and-add',
        Montgomery.pointsEqual(
            Montgomery.scalarMulFull(k, g), _naiveMul(k, g)));
  }

  final negG = Montgomery.scalarMulFull(BigInt.from(-1), g);
  _check('-G == (x(G), -y(G))',
      Montgomery.pointsEqual(negG, Montgomery.negate(g)));

  _check('n * G is infinity', Montgomery.scalarMulFull(n, g).isInfinity);

  print('');
  print('Test 3 - Identity handling:');
  final inf = MontgomeryPoint.infinity();
  _check(
      'infinity + G == G', Montgomery.pointsEqual(Montgomery.add(inf, g), g));
  _check('infinity is equal to itself',
      Montgomery.pointsEqual(inf, MontgomeryPoint.infinity()));
  _check('infinity is not equal to G', !Montgomery.pointsEqual(inf, g));

  print('');
  print('Test 4 - Low-order points:');
  final order2 = MontgomeryPoint(BigInt.zero, BigInt.zero);
  _check(
      '(0, 0) is rejected by isValidPoint', !Montgomery.isValidPoint(order2));
  _check('2 * (0, 0) is infinity',
      Montgomery.scalarMulFull(BigInt.two, order2).isInfinity);
  _check('(0, 0) is not in the prime-order subgroup',
      !Montgomery.isInPrimeOrderSubgroup(order2));

  final x4 = Curve256189Params.p - BigInt.one;
  final y4 = Montgomery.yFromX(x4)!;
  final order4 = MontgomeryPoint(x4, y4);
  _check('order-4 point is rejected by isValidPoint',
      !Montgomery.isValidPoint(order4));

  print('');
  print('Test 5 - x-coordinate decoding:');
  final decoded = Montgomery.pointFromX(g.x);
  _check('pointFromX recovers G', decoded != null && decoded.y == g.y);
  _check('pointFromX chooses an even y', decoded != null && decoded.y.isEven);
  _check(
      'pointFromX rejects x = 0', Montgomery.pointFromX(BigInt.zero) == null);
  _check('pointFromX rejects x = p',
      Montgomery.pointFromX(Curve256189Params.p) == null);

  print('');
  print('Test 6 - Blinding consistency:');
  final k = BigInt.parse('12345678901234567890');
  final unblinded = Montgomery.scalarMulFull(k, g);
  final blinded = Montgomery.scalarMulFull(k, g, blind: true);
  _check('blinded result equals unblinded result',
      Montgomery.pointsEqual(unblinded, blinded));
  final x1 = Montgomery.ladderXOnly(k, g.x, blind: true);
  final x2 = Montgomery.ladderXOnly(k, g.x, blind: true);
  _check('ladderXOnly is deterministic under blinding', x1 == x2);
  _check('ladderXOnly(n) is null',
      Montgomery.ladderXOnly(n, g.x, blind: false) == null);

  print('');
  print('Test 7 - Subgroup validation:');
  _check(
      'G is in the prime-order subgroup', Montgomery.isInPrimeOrderSubgroup(g));
  _check('G.x is a valid public key', Montgomery.isValidPublicKeyX(g.x));
  _check('x = 0 is not a valid public key',
      !Montgomery.isValidPublicKeyX(BigInt.zero));

  print('');
  print('=== Results: $_passed passed, $_failed failed ===');
}
