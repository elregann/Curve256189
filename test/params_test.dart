import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

void main() {
  final p = Curve256189Params.p;
  final n = Curve256189Params.n;

  test('p = 2^256 - 189 and p = 3 mod 8', () {
    expect(p, (BigInt.one << 256) - BigInt.from(189));
    expect(p % BigInt.from(8), BigInt.from(3));
  });

  test('curve coefficients are consistent', () {
    expect(Curve256189Params.A, BigInt.from(61370));
    expect(Curve256189Params.d, Curve256189Params.A - BigInt.two);
    expect(
      FieldElement.mul(Curve256189Params.a24, BigInt.from(4)),
      FieldElement.add(Curve256189Params.A, BigInt.two),
    );
  });

  test(
      'A^2 - 4 is a non-square (x^2 + Ax + 1 has no roots, so (0,0) is the only order-2 point)',
      () {
    final disc = FieldElement.sub(
        FieldElement.mul(Curve256189Params.A, Curve256189Params.A),
        BigInt.from(4));
    expect(FieldElement.pow(disc, (p - BigInt.one) >> 1), p - BigInt.one);
  });

  test('group order n matches the documented value', () {
    expect(
      n,
      BigInt.parse(
          '28948022309329048855892746252171976963404671476872247083542990644359122995957'),
    );
    // Hasse: |#E - (p + 1)| <= 2 sqrt(p), with #E = 4n and trace t.
    final trace = p + BigInt.one - BigInt.from(4) * n;
    expect(
      trace,
      BigInt.parse('-348701241848424294714378569523362344080'),
    );
    expect(trace * trace < BigInt.from(4) * p, isTrue);
  });

  test('base point lies on both curve models', () {
    final g = MontgomeryPoint.G;
    expect(g.x, Curve256189Params.gx);
    expect(g.y, Curve256189Params.gy);
    expect(Montgomery.isOnCurve(g), isTrue);

    final ed = TwistedEdwards.fromMontgomery(g);
    expect(ed.x, Curve256189Params.gxEd);
    expect(ed.y, Curve256189Params.gyEd);
    expect(TwistedEdwards.isOnCurve(ed), isTrue);
  });

  test('G has order n', () {
    expect(Montgomery.scalarMulFull(n, MontgomeryPoint.G).isInfinity, isTrue);
    expect(
      Montgomery.scalarMulFull(n - BigInt.one, MontgomeryPoint.G).isInfinity,
      isFalse,
    );
  });

  test('twist order is 4 * nt (documented value)', () {
    final twist = BigInt.two * (p + BigInt.one) - BigInt.from(4) * n;
    expect(
      twist,
      BigInt.from(4) *
          BigInt.parse(
              '28948022309329048855892746252171976963230320855948034936185801359597441823917'),
    );
  });

  test('embedding degree is larger than 50 (p^k != 1 mod n)', () {
    var power = BigInt.one;
    for (var k = 1; k <= 50; k++) {
      power = (power * p) % n;
      expect(power, isNot(BigInt.one), reason: 'k=$k');
    }
  });

  test('curve order and twist order have no small odd factors', () {
    final order = BigInt.from(4) * n;
    final twist = BigInt.two * (p + BigInt.one) - order;
    for (var q = 3; q < 1000; q += 2) {
      final bq = BigInt.from(q);
      expect(order % bq, isNot(BigInt.zero), reason: 'q=$q');
      expect(twist % bq, isNot(BigInt.zero), reason: 'q=$q');
    }
  });
}
