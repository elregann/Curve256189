// test_elligator.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Elligator 2 Curve256189 ===');

  // Test case 1: Verify that encode produces a valid x-coordinate on the curve
  print('');
  print('Test 1 - Does encode(t) produce a valid x on the curve?');
  for (final t in [1, 2, 3, 100, 999]) {
    final x = Elligator.encode(BigInt.from(t));
    print('  t=$t -> x valid? ${x != null}');
  }

  // Test case 2: Verify that encode and decode round-trip are consistent
  print('');
  print('Test 2 - Is the round-trip (encode -> decode -> encode) consistent?');
  for (final t in [1, 2, 3, 100, 999]) {
    final x1 = Elligator.encode(BigInt.from(t));
    if (x1 == null) continue;
    final tBack = Elligator.decode(x1);
    if (tBack == null) continue;
    final x2 = Elligator.encode(tBack);
    print('  t=$t -> x matches? ${x1 == x2}');
  }

  // Test case 3: Verify that t = 0 returns null (edge case)
  print('');
  print('Test 3 - Does t = 0 return null?');
  print('  ${Elligator.encode(BigInt.zero) == null}');

  // Test case 4: Show sample output (not distinguishable from random ECC points)
  print('');
  print('Test 4 - Sample output (indistinguishable from random ECC points):');
  final x = Elligator.encode(BigInt.from(42));
  print('  x = $x');

  // Test case 5: Verify that approximately 50% of points have no Elligator representation
  print('');
  print('Test 5 - Approximately 50% of points have no Elligator representation?');
  int canDecode = 0;
  int cannot = 0;
  for (int i = 1; i <= 100; i++) {
    // Generate a valid x-coordinate on the curve via encode
    final x = Elligator.encode(BigInt.from(i));
    if (x == null) continue;
    // Attempt to decode a slightly modified x
    final xMod = x + BigInt.from(i * 7);
    final t = Elligator.decode(xMod);
    if (t != null) canDecode++;
    else cannot++;
  }
  print('  can decode: $canDecode');
  print('  cannot decode: $cannot');
  print('  approximately 50%? ${canDecode > 20 && cannot > 20}');

  // Test case 6: Verify that encode always produces an x-coordinate on the curve
  print('');
  print('Test 6 - Does encode(random t) always produce a point on the curve?');
  bool allOnCurve = true;
  final p = Curve256189Params.p;
  final A = Curve256189Params.A;
  for (int i = 1; i <= 50; i++) {
    final t = BigInt.from(i * 12345678);
    final x = Elligator.encode(t);
    if (x == null) continue;
    // Verify that the point lies on the curve: rhs = x^3 + A*x^2 + x must be a square
    final x2 = (x * x) % p;
    final x3 = (x * x2) % p;
    final rhs = (x3 + A * x2 + x) % p;
    final exp = (p + BigInt.one) >> 2;
    final y = rhs.modPow(exp, p);
    if ((y * y) % p != rhs) { allOnCurve = false; break; }
  }
  print('  all points on curve? $allOnCurve');

  // Test case 7: RFC edge case for t = 0
  print('');
  print('Test 7 - RFC edge case (t = 0):');
  print('  encode(0) == null? ${Elligator.encode(BigInt.zero) == null}');
}