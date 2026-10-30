// test_modpow.dart

import 'package:curve256189/curve256189.dart';

// Reference implementation of modular exponentiation for comparison.
BigInt modPowSafe(BigInt base, BigInt exp, BigInt mod) {
  BigInt result = BigInt.one;
  base = base % mod;
  while (exp > BigInt.zero) {
    if (exp.isOdd) result = (result * base) % mod;
    exp = exp >> 1;
    base = (base * base) % mod;
  }
  return result;
}

void main() {
  print('=== Audit: modPow in Curve256189 ===');

  final p = Curve256189Params.p;
  final A = Curve256189Params.A;
  final exp = (p + BigInt.one) >> 2;  // Exponent for square root computation

  // Test case 1: Square root in Montgomery scalarMul (right-hand side of 2G)
  print('');
  print('Test 1 - Square root in Montgomery scalarMul (rhs of 2G):');
  final G = MontgomeryPoint.G;
  final xR = Montgomery.ladderXOnly(BigInt.two, G.x);
  final x2 = FieldElement.mul(xR, xR);
  final x3 = FieldElement.mul(xR, x2);
  final rhs = FieldElement.add(
    FieldElement.add(x3, FieldElement.mul(A, x2)),
    xR,
  );
  final y_modpow = rhs.modPow(exp, p);
  final y_safe = modPowSafe(rhs, exp, p);
  print('  equal?              = ${y_modpow == y_safe}');
  print('  modPow verification = ${FieldElement.mul(y_modpow, y_modpow) == rhs}');
  print('  safe verification   = ${FieldElement.mul(y_safe, y_safe) == rhs}');

  // Test case 2: Square root in Edwards decodePoint (x^2 from G.y)
  print('');
  print('Test 2 - Square root in Edwards decodePoint (x^2 from G.y):');
  final Ged = TwistedEdwards.fromMontgomery(G);
  final a = FieldElement.add(A, BigInt.two);
  final d = FieldElement.sub(A, BigInt.two);
  final y2 = FieldElement.mul(Ged.y, Ged.y);
  final num = FieldElement.sub(BigInt.one, y2);
  final den = FieldElement.sub(a, FieldElement.mul(d, y2));
  final x2ed = FieldElement.mul(num, FieldElement.inv(den));
  final x_modpow = x2ed.modPow(exp, p);
  final x_safe = modPowSafe(x2ed, exp, p);
  print('  equal?              = ${x_modpow == x_safe}');
  print('  modPow verification = ${FieldElement.mul(x_modpow, x_modpow) == x2ed}');
  print('  safe verification   = ${FieldElement.mul(x_safe, x_safe) == x2ed}');

  // Test case 3: Square root with a known problematic large value
  print('');
  print('Test 3 - Square root with a known problematic large value:');
  final bigVal = BigInt.parse('77194726158210796949047323339125271902179989777093709359638389338608752933299');
  final sq = FieldElement.mul(bigVal, bigVal);
  final sq_modpow = sq.modPow(exp, p);
  final sq_safe = modPowSafe(sq, exp, p);
  print('  equal?              = ${sq_modpow == sq_safe}');
  print('  modPow verification = ${FieldElement.mul(sq_modpow, sq_modpow) == sq}');
  print('  safe verification   = ${FieldElement.mul(sq_safe, sq_safe) == sq}');

  // Test case 4: Modular inverse via modPow (exponent = p-2) compared to safe implementation
  print('');
  print('Test 4 - Modular inverse via modPow (exp = p-2) vs safe implementation:');
  final testVal = BigInt.parse('77194726158210796949047323339125271902179989777093709359638389338608752453702');
  final expInv = p - BigInt.two;

  final inv_modpow = testVal.modPow(expInv, p);
  final inv_safe = modPowSafe(testVal, expInv, p);
  print('  equal?              = ${inv_modpow == inv_safe}');
  print('  modPow verification = ${FieldElement.mul(testVal, inv_modpow) == BigInt.one}');
  print('  safe verification   = ${FieldElement.mul(testVal, inv_safe) == BigInt.one}');

  // Test case 5: Modular inverse with a different random value
  print('');
  print('Test 5 - Modular inverse with a different value:');
  final testVal2 = BigInt.parse('64328938465175664124206102782604393251816658147578091133031991115507293391687');
  final inv2_modpow = testVal2.modPow(expInv, p);
  final inv2_safe = modPowSafe(testVal2, expInv, p);
  print('  equal?              = ${inv2_modpow == inv2_safe}');
  print('  modPow verification = ${FieldElement.mul(testVal2, inv2_modpow) == BigInt.one}');
  print('  safe verification   = ${FieldElement.mul(testVal2, inv2_safe) == BigInt.one}');

  // Test case 6: Square root for a value derived from t=2 (known problematic)
  print('');
  print('Test 6 - Square root for value from t=2 (known problematic):');
  final t2_val = BigInt.parse('36185027886661311069865932815214971204146870208012676262330495002472853012421');
  final sqrt_modpow = t2_val.modPow(exp, p);
  final sqrt_safe = modPowSafe(t2_val, exp, p);
  print('  equal?              = ${sqrt_modpow == sqrt_safe}');
  print('  modPow verification = ${FieldElement.mul(sqrt_modpow, sqrt_modpow) == t2_val}');
  print('  safe verification   = ${FieldElement.mul(sqrt_safe, sqrt_safe) == t2_val}');
}