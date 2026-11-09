// tool/twist_analysis.dart

// Twist Curve Security Analysis for Curve256189
//
// For X-only Diffie-Hellman (X256189), the twist curve must have no
// dangerous small subgroup factors to prevent twist attacks.
// An attacker sends a point on the twist and learns private key bits
// from small subgroup confinement.
//
// Note: A twist cofactor of 4 (= 2^2) is EXPECTED and SAFE for curves
// with a main curve cofactor of 4. Only odd small factors are dangerous.

import 'package:curve256189/curve256189.dart';

// Miller-Rabin primality test.
//
// The bases are fixed so that repeated runs are reproducible. With 32 bases,
// the probability that a composite passes every round is at most 4^-32
// (about 2^-64), which is negligible for the offline inputs used here. This
// is a probabilistic test, not a primality proof.
//
// Dart's BigInt.modPow is deliberately avoided: this repository has observed
// incorrect results from it for some 256-bit inputs (see field.dart).
bool _isPrime(BigInt n) {
  if (n < BigInt.two) return false;
  if (n == BigInt.two || n == BigInt.from(3)) return true;
  if (n.isEven) return false;

  const bases = <int>[
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
  ];

  // Trial division by the bases catches small composites early.
  for (final base in bases) {
    final a = BigInt.from(base);
    if (a >= n) break;
    if (n % a == BigInt.zero) return n == a;
  }

  var d = n - BigInt.one;
  var s = 0;
  while (d.isEven) {
    d >>= 1;
    s++;
  }

  for (final base in bases) {
    final a = BigInt.from(base);
    if (a >= n) break;

    var x = _modPow(a, d, n);
    if (x == BigInt.one || x == n - BigInt.one) continue;

    var composite = true;
    for (var r = 1; r < s; r++) {
      x = (x * x) % n;
      if (x == n - BigInt.one) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }

  return true;
}

// Modular exponentiation without BigInt.modPow.
BigInt _modPow(BigInt base, BigInt exponent, BigInt modulus) {
  var result = BigInt.one;
  var b = base % modulus;
  var e = exponent;
  while (e > BigInt.zero) {
    if (e.isOdd) result = (result * b) % modulus;
    e >>= 1;
    b = (b * b) % modulus;
  }
  return result;
}

void main() {
  print('Curve256189 Twist Security Test');
  print('');

  final p = Curve256189Params.p;
  final n = Curve256189Params.n;

  // The full curve order is 4 * n (cofactor * subgroup order)
  final curveOrder = n * BigInt.from(4);

  // Trace of Frobenius: t = p + 1 - curve_order
  // IMPORTANT: Use curve_order (= 4 * n), not n alone.
  final t = p + BigInt.one - curveOrder;

  print('Curve Parameters:');
  print('  p (field modulus)      = $p');
  print('  n (subgroup order)     = $n');
  print('  curve order (4 * n)    = $curveOrder');
  print('  t (trace of Frobenius) = $t');
  print('');

  // Twist order formula: p + 1 + t = 2 * (p + 1) - curve_order
  final twistOrder = p + BigInt.one + t;
  print('Twist Curve:');
  print('  twist order = $twistOrder');
  print('');

  // Step 1: Extract the power-of-2 cofactor from the twist order
  // A cofactor of 4 = 2^2 is EXPECTED for this curve
  BigInt remaining = twistOrder;
  int powerOf2 = 0;
  while (remaining % BigInt.two == BigInt.zero) {
    remaining ~/= BigInt.two;
    powerOf2++;
  }
  final twistCofactor = BigInt.two.pow(powerOf2);
  final twistSubgroup = remaining;

  print('Twist Cofactor Analysis:');
  print('  twist cofactor = 2^$powerOf2 = $twistCofactor');
  print('  twist subgroup = $twistSubgroup');
  print('');

  // Step 2: Check whether the twist subgroup is prime
  final subgroupPrime = _isPrime(twistSubgroup);
  print('  Is the twist subgroup prime? $subgroupPrime');
  print('');

  // Step 3: Check for dangerous ODD small factors in the twist order
  // A power-of-2 cofactor is expected; only odd factors are dangerous.
  print('Dangerous Factor Analysis:');
  print('  Checking for odd small prime factors...');

  final oddPrimes = [
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
  ];

  final dangerousFactors = <int>[];
  for (final prime in oddPrimes) {
    if (twistOrder % BigInt.from(prime) == BigInt.zero) {
      dangerousFactors.add(prime);
    }
  }

  if (dangerousFactors.isEmpty) {
    print('  No dangerous odd factors found.');
  } else {
    print('  Dangerous odd factors found: $dangerousFactors');
  }
  print('');

  // Final security verdict
  print('Security Verdict:');
  final safe = powerOf2 <= 3 && subgroupPrime && dangerousFactors.isEmpty;

  if (safe) {
    print('  Twist cofactor = $twistCofactor (safe: power of 2 only).');
    print('  Twist subgroup is prime.');
    print('  No dangerous odd small factors.');
    print('  Curve256189 is SAFE for X-only ECDH (X256189).');
    print('  SafeCurves criterion 9: PASS.');
  } else {
    print('  Twist has dangerous factors.');
    if (powerOf2 > 3) {
      print('    Power-of-2 cofactor is too large: 2^$powerOf2');
    }
    if (!subgroupPrime) {
      print('    Twist subgroup is not prime');
    }
    if (dangerousFactors.isNotEmpty) {
      print('    Dangerous odd factors: $dangerousFactors');
    }
  }
  print('');
  print('=== Twist Security Test Completed ===');
}
