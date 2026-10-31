// test_edwards.dart

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
  print('=== Test: Twisted Edwards Operations ===');
  print('');

  final gMont = MontgomeryPoint.G;
  final gEd = TwistedEdwards.fromMontgomery(gMont);
  final n = Curve256189Params.n;

  print('Test 1 - Parameters and base point:');
  print('  a = ${TwistedEdwards.a}');
  print('  d = ${TwistedEdwards.d}');
  _check('base point lies on the Edwards curve', TwistedEdwards.isOnCurve(gEd));

  print('');
  print('Test 2 - Birational round-trip:');
  final roundTrip = TwistedEdwards.toMontgomery(gEd);
  _check('G -> Edwards -> Montgomery returns G',
      roundTrip.x == gMont.x && roundTrip.y == gMont.y);

  print('');
  print('Test 3 - Group law:');
  final g2Ed = TwistedEdwards.add(gEd, gEd);
  final g2Mont = TwistedEdwards.fromMontgomery(Montgomery.double_(gMont));
  _check('G + G == 2G', g2Ed.x == g2Mont.x && g2Ed.y == g2Mont.y);
  _check('G + G is on the curve', TwistedEdwards.isOnCurve(g2Ed));

  final g3Ed = TwistedEdwards.add(g2Ed, gEd);
  final g3Scalar = TwistedEdwards.scalarMul(BigInt.from(3), gEd);
  _check('2G + G == 3G', g3Ed.x == g3Scalar.x && g3Ed.y == g3Scalar.y);

  print('');
  print('Test 4 - Scalar multiplication via full Montgomery arithmetic:');
  final g4Scalar = TwistedEdwards.scalarMul(BigInt.from(4), gEd);
  final g4Double = TwistedEdwards.add(g2Ed, g2Ed);
  _check('4G == 2(2G)', g4Scalar.x == g4Double.x && g4Scalar.y == g4Double.y);

  final gNeg = TwistedEdwards.scalarMul(-BigInt.one, gEd);
  final gNegExpected = TwistedEdwards.negate(gEd);
  _check(
      '-G == negate(G)', gNeg.x == gNegExpected.x && gNeg.y == gNegExpected.y);

  final nG = TwistedEdwards.scalarMul(n, gEd);
  _check('n * G is the neutral point (0, 1)',
      nG.x == BigInt.zero && nG.y == BigInt.one);

  print('');
  print('Test 5 - Point compression round-trip:');
  final encoded = TwistedEdwards.encodePoint(g3Ed);
  final decoded = TwistedEdwards.decodePoint(encoded);
  _check('3G survives encode/decode',
      decoded != null && decoded.x == g3Ed.x && decoded.y == g3Ed.y);

  print('');
  print('Test 6 - Exceptional order-4 chart:');
  final p = Curve256189Params.p;
  final x4 = p - BigInt.one;
  final y4 = Montgomery.yFromX(x4)!;
  var threw = false;
  try {
    TwistedEdwards.fromMontgomery(MontgomeryPoint(x4, y4));
  } on StateError {
    threw = true;
  }
  _check('order-4 Montgomery point is rejected by the Edwards chart', threw);

  print('');
  print('=== Results: $_passed passed, $_failed failed ===');
}
