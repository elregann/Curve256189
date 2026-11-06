// test_modpow.dart

import 'dart:math';
import 'package:curve256189/curve256189.dart';

BigInt referencePow(BigInt base, BigInt exp, BigInt mod) {
  BigInt result = BigInt.one;
  base = base % mod;
  while (exp > BigInt.zero) {
    if (exp.isOdd) result = (result * base) % mod;
    exp = exp >> 1;
    base = (base * base) % mod;
  }
  return result;
}

BigInt randomBits(Random rng, int bits) {
  var v = BigInt.zero;
  for (var i = 0; i < bits; i += 32) {
    v = (v << 32) | BigInt.from(rng.nextInt(0x100000000));
  }
  return v & ((BigInt.one << bits) - BigInt.one);
}

void expect(bool condition, String message) {
  if (!condition) throw StateError('FAILED: $message');
}

void main() {
  final p = Curve256189Params.p;
  final half = (p - BigInt.one) >> 1;
  final sqrtExp = (p + BigInt.one) >> 2;
  final exps = [sqrtExp, p - BigInt.two, half];

  print('=== Test: known answers ===');
  expect(FieldElement.pow(p - BigInt.one, half) == p - BigInt.one, '(p-1)^half');
  expect(FieldElement.pow(half + BigInt.one, p - BigInt.two) == BigInt.two,
      '(half+1)^(p-2) == 2');
  expect(FieldElement.pow(p - BigInt.one, p - BigInt.two) == p - BigInt.one,
      '(p-1)^(p-2)');
  final rootOfHalf = FieldElement.pow(half, sqrtExp);
  expect(FieldElement.mul(rootOfHalf, rootOfHalf) == half, 'sqrt(half)');
  print('  known answers ok');

  print('=== Test: structured inputs vs reference ===');
  final bases = <BigInt>[];
  for (var k = 0; k < 300; k++) {
    final bk = BigInt.from(k);
    bases.addAll([bk, p - bk, half + bk, half - bk]);
  }
  for (var s = 0; s < 256; s++) {
    final b = BigInt.one << s;
    bases.addAll([b % p, (b - BigInt.one) % p, (b + BigInt.one) % p]);
  }
  var structured = 0;
  var dartModPowWrong = 0;
  for (final b in bases) {
    for (final e in exps) {
      final want = referencePow(b, e, p);
      expect(FieldElement.pow(b, e) == want, 'pow mismatch base=$b exp=$e');
      if (b.modPow(e, p) != want) dartModPowWrong++;
      structured++;
    }
  }
  print('  $structured structured cases match');
  print('  informational: Dart BigInt.modPow was wrong on $dartModPowWrong');

  print('=== Test: random inputs vs reference ===');
  final rng = Random(189);
  var total = 0;
  for (var i = 0; i < 20000; i++) {
    final base = randomBits(rng, 256) % p;
    final e = i < 15000 ? exps[i % 3] : randomBits(rng, 256);
    expect(
      FieldElement.pow(base, e) == referencePow(base, e, p),
      'pow mismatch base=$base exp=$e',
    );
    total++;
  }
  print('  $total random cases match');

  print('=== Test: edge cases ===');
  expect(FieldElement.pow(BigInt.zero, BigInt.zero) == BigInt.one, '0^0');
  expect(FieldElement.pow(BigInt.two, BigInt.zero) == BigInt.one, '2^0');
  expect(FieldElement.pow(p + BigInt.two, BigInt.one) == BigInt.two, 'a >= p');
  expect(FieldElement.pow(-BigInt.one, BigInt.two) == BigInt.one, 'a < 0');
  var threw = false;
  try {
    FieldElement.pow(BigInt.two, -BigInt.one);
  } on ArgumentError {
    threw = true;
  }
  expect(threw, 'negative exponent must throw');
  print('  edge cases ok');

  print('=== Test: Elligator 2 test vectors ===');
  final vectors = {
    1: '38597363079105398474523661669562635951089994888546854679819194669304376226851',
    2: '90060513851245929773888543895646150552543321406609327586244787561710211515717',
    42: '51481379431382575976079023938405023355562653992742999427007353161920005302563',
  };
  vectors.forEach((t, want) {
    final x = Elligator.encode(BigInt.from(t));
    expect(x != null && x == BigInt.parse(want), 'encode($t) vector');
    expect(Montgomery.yFromX(x!) != null, 'encode($t) lies on the curve');
  });
  print('  vectors ok');

  print('All checks passed.');
}
