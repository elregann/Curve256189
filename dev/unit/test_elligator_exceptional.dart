// test_elligator_exceptional.dart

import 'package:curve256189/curve256189.dart';

void expect(bool condition, String message) {
  if (!condition) throw StateError('FAILED: $message');
}

void main() {
  print('=== Test: Elligator 2 exceptional case 1 + u*t^2 == 0 ===');

  final p = Curve256189Params.p;
  final A = Curve256189Params.A;
  final u = Elligator.u;
  final xExceptional = FieldElement.sub(BigInt.zero, A);

  final minusInvU = FieldElement.sub(BigInt.zero, FieldElement.inv(u));
  final t0 = FieldElement.pow(minusInvU, (p + BigInt.one) >> 2);
  expect(FieldElement.mul(t0, t0) == minusInvU, 'sqrt(-1/u) exists');

  final denom = FieldElement.add(
    BigInt.one,
    FieldElement.mul(u, FieldElement.mul(t0, t0)),
  );
  expect(denom == BigInt.zero, '1 + u*t0^2 == 0');
  print('  exceptional t found');

  for (final t in [t0, FieldElement.sub(BigInt.zero, t0)]) {
    final x = Elligator.encode(t);
    expect(x != null, 'encode returns a value');
    expect(x != BigInt.zero, 'encode must not return the order 2 point');
    expect(x == xExceptional, 'encode returns -A as RFC 9380 requires');
    expect(Montgomery.yFromX(x!) != null, 'result lies on the curve');
  }
  print('  encode(t) == -A for both signs of t');

  final half = p >> 1;
  final canonical = t0 <= half ? t0 : FieldElement.sub(BigInt.zero, t0);
  final decoded = Elligator.decode(xExceptional);
  expect(decoded != null, 'decode(-A) is not null');
  expect(decoded == canonical, 'decode(-A) returns the canonical exceptional t');
  expect(Elligator.encode(decoded!) == xExceptional, 'round trip at -A');
  print('  decode(-A) round trip ok');

  final vectors = {
    1: '38597363079105398474523661669562635951089994888546854679819194669304376226851',
    2: '90060513851245929773888543895646150552543321406609327586244787561710211515717',
    42: '51481379431382575976079023938405023355562653992742999427007353161920005302563',
  };
  vectors.forEach((t, want) {
    expect(
      Elligator.encode(BigInt.from(t)) == BigInt.parse(want),
      'vector encode($t) unchanged',
    );
  });
  print('  README vectors unchanged');

  print('All checks passed.');
}
