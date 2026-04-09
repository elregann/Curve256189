// test_modpow.dart

import 'package:curve256189/curve256189.dart';

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
  print('=== Audit modPow Curve256189 ===');

  final p = Curve256189Params.p;
  final A = Curve256189Params.A;
  final exp = (p + BigInt.one) >> 2;

  // Test 1: sqrt di Montgomery scalarMul (rhs dari 2G)
  print('\nTest 1 - sqrt di Montgomery scalarMul (rhs dari 2G):');
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
  print('  sama?          = ${y_modpow == y_safe}');
  print('  modPow verify  = ${FieldElement.mul(y_modpow, y_modpow) == rhs}');
  print('  safe   verify  = ${FieldElement.mul(y_safe, y_safe) == rhs}');

  // Test 2: sqrt di Edwards decodePoint (x² dari G.y)
  print('\nTest 2 - sqrt di Edwards decodePoint (x² dari G.y):');
  final Ged = TwistedEdwards.fromMontgomery(G);
  final a = FieldElement.add(A, BigInt.two);
  final d = FieldElement.sub(A, BigInt.two);
  final y2 = FieldElement.mul(Ged.y, Ged.y);
  final num = FieldElement.sub(BigInt.one, y2);
  final den = FieldElement.sub(a, FieldElement.mul(d, y2));
  final x2ed = FieldElement.mul(num, FieldElement.inv(den));
  final x_modpow = x2ed.modPow(exp, p);
  final x_safe = modPowSafe(x2ed, exp, p);
  print('  sama?          = ${x_modpow == x_safe}');
  print('  modPow verify  = ${FieldElement.mul(x_modpow, x_modpow) == x2ed}');
  print('  safe   verify  = ${FieldElement.mul(x_safe, x_safe) == x2ed}');

  // Test 3: sqrt dengan nilai besar yang diketahui bermasalah
  print('\nTest 3 - sqrt dengan nilai besar (known problematic):');
  final bigVal = BigInt.parse('77194726158210796949047323339125271902179989777093709359638389338608752933299');
  final sq = FieldElement.mul(bigVal, bigVal);
  final sq_modpow = sq.modPow(exp, p);
  final sq_safe = modPowSafe(sq, exp, p);
  print('  sama?          = ${sq_modpow == sq_safe}');
  print('  modPow verify  = ${FieldElement.mul(sq_modpow, sq_modpow) == sq}');
  print('  safe   verify  = ${FieldElement.mul(sq_safe, sq_safe) == sq}');

  // Tambahkan di test_modpow.dart
  print('\nTest 4 - inv via modPow (exp = p-2) vs safe:');
  final testVal = BigInt.parse('77194726158210796949047323339125271902179989777093709359638389338608752453702');
  final expInv = p - BigInt.two;

  final inv_modpow = testVal.modPow(expInv, p);
  final inv_safe = modPowSafe(testVal, expInv, p);
  print('  sama?          = ${inv_modpow == inv_safe}');
  print('  modPow verify  = ${FieldElement.mul(testVal, inv_modpow) == BigInt.one}');
  print('  safe   verify  = ${FieldElement.mul(testVal, inv_safe) == BigInt.one}');

  // Test dengan nilai lain
  print('\nTest 5 - inv dengan nilai berbeda:');
  final testVal2 = BigInt.parse('64328938465175664124206102782604393251816658147578091133031991115507293391687');
  final inv2_modpow = testVal2.modPow(expInv, p);
  final inv2_safe = modPowSafe(testVal2, expInv, p);
  print('  sama?          = ${inv2_modpow == inv2_safe}');
  print('  modPow verify  = ${FieldElement.mul(testVal2, inv2_modpow) == BigInt.one}');
  print('  safe   verify  = ${FieldElement.mul(testVal2, inv2_safe) == BigInt.one}');

  // Tambahkan di test_modpow.dart
  print('\nTest 6 - sqrt untuk nilai dari t=2 (known problematic):');
  final t2_val = BigInt.parse('36185027886661311069865932815214971204146870208012676262330495002472853012421');
  final sqrt_modpow = t2_val.modPow(exp, p);
  final sqrt_safe = modPowSafe(t2_val, exp, p);
  print('  sama?          = ${sqrt_modpow == sqrt_safe}');
  print('  modPow verify  = ${FieldElement.mul(sqrt_modpow, sqrt_modpow) == t2_val}');
  print('  safe   verify  = ${FieldElement.mul(sqrt_safe, sqrt_safe) == t2_val}');
}