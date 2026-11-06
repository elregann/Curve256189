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
  print('=== Test: FieldElement.pow vs reference square and multiply ===');

  final p = Curve256189Params.p;
  final rng = Random(189);
  final exps = [(p + BigInt.one) >> 2, p - BigInt.two, (p - BigInt.one) >> 1];

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
