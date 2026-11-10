import 'dart:math';

import 'package:curve256189/curve256189.dart';
import 'package:test/test.dart';

BigInt _referencePow(BigInt base, BigInt exp, BigInt mod) {
  var result = BigInt.one;
  base = base % mod;
  while (exp > BigInt.zero) {
    if (exp.isOdd) result = (result * base) % mod;
    exp >>= 1;
    base = (base * base) % mod;
  }
  return result;
}

BigInt _randomBits(Random rng, int bits) {
  var v = BigInt.zero;
  for (var i = 0; i < bits; i += 32) {
    v = (v << 32) | BigInt.from(rng.nextInt(0x100000000));
  }
  return v & ((BigInt.one << bits) - BigInt.one);
}

void main() {
  final p = Curve256189Params.p;
  final half = (p - BigInt.one) >> 1;
  final sqrtExp = (p + BigInt.one) >> 2;

  group('add / sub / mul', () {
    final a = BigInt.parse('123456789012345678901234567890');
    final b = BigInt.parse('987654321098765432109876543210');

    test('small values', () {
      expect(FieldElement.add(a, b), a + b);
      expect(FieldElement.mul(a, b), (a * b) % p);
      expect(FieldElement.sub(b, a), b - a);
    });

    test('wrap around p', () {
      expect(FieldElement.add(p - BigInt.one, BigInt.two), BigInt.one);
      expect(FieldElement.sub(BigInt.zero, BigInt.one), p - BigInt.one);
      expect(FieldElement.sub(a, b), p - (b - a));
      expect(FieldElement.mul(p - BigInt.one, p - BigInt.one), BigInt.one);
    });

    test('results are always reduced', () {
      for (final v in [BigInt.zero, BigInt.one, p - BigInt.one, half]) {
        expect(FieldElement.add(v, v) < p, isTrue);
        expect(FieldElement.sub(v, p - BigInt.one) >= BigInt.zero, isTrue);
        expect(FieldElement.mul(v, v) < p, isTrue);
      }
    });
  });

  group('inv / inv0', () {
    test('a * inv(a) == 1', () {
      final rng = Random(1);
      for (var i = 0; i < 200; i++) {
        final a = _randomBits(rng, 256) % (p - BigInt.one) + BigInt.one;
        expect(FieldElement.mul(a, FieldElement.inv(a)), BigInt.one);
      }
      expect(FieldElement.inv(BigInt.one), BigInt.one);
      expect(FieldElement.inv(p - BigInt.one), p - BigInt.one);
      expect(FieldElement.inv(BigInt.two), (p + BigInt.one) >> 1);
    });

    test('inv(0) throws', () {
      expect(() => FieldElement.inv(BigInt.zero), throwsArgumentError);
      expect(() => FieldElement.inv(p), throwsArgumentError);
    });

    test('inv0(0) == 0 and inv0 matches inv otherwise', () {
      expect(FieldElement.inv0(BigInt.zero), BigInt.zero);
      expect(
          FieldElement.inv0(BigInt.from(7)), FieldElement.inv(BigInt.from(7)));
    });
  });

  group('pow', () {
    // Regression: Dart's BigInt.modPow returns wrong results for some
    // structured 256-bit inputs. These known answers must hold.
    test('known answers on structured inputs', () {
      expect(FieldElement.pow(p - BigInt.one, half), p - BigInt.one);
      expect(FieldElement.pow(half + BigInt.one, p - BigInt.two), BigInt.two);
      expect(FieldElement.pow(p - BigInt.one, p - BigInt.two), p - BigInt.one);
      final root = FieldElement.pow(half, sqrtExp);
      expect(FieldElement.mul(root, root), half);
    });

    test('Fermat: a^(p-1) == 1', () {
      for (final a in [BigInt.two, BigInt.from(12345), p - BigInt.two, half]) {
        expect(FieldElement.pow(a, p - BigInt.one), BigInt.one);
      }
    });

    test('2 and -1 are non-squares (p = 3 mod 8)', () {
      expect(FieldElement.pow(BigInt.two, half), p - BigInt.one);
      expect(FieldElement.pow(p - BigInt.one, half), p - BigInt.one);
    });

    test('structured bases match the reference implementation', () {
      final exps = [sqrtExp, p - BigInt.two, half];
      final bases = <BigInt>[];
      for (var k = 0; k < 100; k++) {
        final bk = BigInt.from(k);
        bases.addAll([bk, p - bk, half + bk, half - bk]);
      }
      for (var s = 0; s < 256; s += 3) {
        final b = BigInt.one << s;
        bases.addAll([b % p, (b - BigInt.one) % p, (b + BigInt.one) % p]);
      }
      for (final b in bases) {
        for (final e in exps) {
          expect(FieldElement.pow(b, e), _referencePow(b, e, p),
              reason: 'base=$b exp=$e');
        }
      }
    });

    test('random inputs match the reference implementation', () {
      final rng = Random(189);
      final exps = [sqrtExp, p - BigInt.two, half];
      for (var i = 0; i < 2000; i++) {
        final base = _randomBits(rng, 256) % p;
        final e = i < 1500 ? exps[i % 3] : _randomBits(rng, 256);
        expect(FieldElement.pow(base, e), _referencePow(base, e, p));
      }
    });

    test('edge cases', () {
      expect(FieldElement.pow(BigInt.zero, BigInt.zero), BigInt.one);
      expect(FieldElement.pow(BigInt.two, BigInt.zero), BigInt.one);
      expect(FieldElement.pow(BigInt.zero, BigInt.from(5)), BigInt.zero);
      expect(FieldElement.pow(p + BigInt.two, BigInt.one), BigInt.two);
      expect(FieldElement.pow(-BigInt.one, BigInt.two), BigInt.one);
      expect(
          () => FieldElement.pow(BigInt.two, -BigInt.one), throwsArgumentError);
    });
  });
}
