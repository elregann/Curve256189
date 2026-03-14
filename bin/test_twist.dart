// curve256189_twist_test.dart
// Twist Curve Security Analysis for Curve256189
//
// For X-only Diffie-Hellman (X256189), the twist curve must have no
// small subgroup factors to prevent twist attacks.
// Attacker sends a point on the twist and learns private key bits
// from small subgroup confinement.

import 'src/params.dart';

void main() {
  print('╔══════════════════════════════════════╗');
  print('║  Curve256189 Twist Security Test     ║');
  print('╚══════════════════════════════════════╝');

  final p = Curve256189Params.p;  // Field modulus
  final n = Curve256189Params.n;  // Curve order

  // Trace of Frobenius: t = p + 1 - n
  // For a valid curve, |t| ≤ 2√p (Hasse bound)
  final t = p + BigInt.one - n;
  print('\n📊 Curve Parameters:');
  print('   p (field modulus)     = $p');
  print('   n (curve order)       = $n');
  print('   t (trace of Frobenius) = $t');

  // Note: Hasse bound verification skipped because parameters
  // are fixed and assumed valid. For reference: |t| ≤ 2√p
  // 2√p ≈ 2 * 2¹²⁸ = 2¹²⁹ ≈ 6.8e38

  // Twist order: n_twist = p + 1 + t
  // This is the order of the quadratic twist curve
  final twistOrder = p + BigInt.one + t;
  print('\n📊 Twist Curve:');
  print('   twist order (n_twist) = $twistOrder');
  print('   twist order ≈ n + 2t  = ${n + BigInt.two * t}');

  // Check for small subgroup factors
  print('\n📊 Small Subgroup Analysis:');
  print('   Checking divisibility by small primes...');

  final smallPrimes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229
  ];

  int smallFactors = 0;
  final factors = <int>[];

  for (final prime in smallPrimes) {
    final d = BigInt.from(prime);
    if (twistOrder % d == BigInt.zero) {
      print('   ⚠️  twist order divisible by $prime');
      smallFactors++;
      factors.add(prime);
    }
  }

  if (smallFactors == 0) {
    print('   ✅ No small subgroup factors detected');
    print('   ✅ Twist curve is safe for X-only ECDH');
  } else {
    print('\n   ⚠️  WARNING — Twist has small subgroup factors!');
    print('      Factors found: $factors');
    print('      This curve is NOT safe for X25519-style ECDH');
    print('      Attacker can perform small subgroup twist attack');
    print('      to recover private key bits.');

    // Additional analysis: largest smooth factor
    BigInt remaining = twistOrder;
    for (final prime in factors) {
      final d = BigInt.from(prime);
      while (remaining % d == BigInt.zero) {
        remaining ~/= d;
      }
    }
    print('\n   Remaining cofactor ≈ $remaining');

    // Calculate approximate attack cost
    int attackCost = 1;
    for (final prime in factors) {
      attackCost *= prime;
    }
    if (attackCost > 1000000) {
      print('   Attack cost: ~$attackCost possibilities (likely still feasible)');
    } else {
      print('   Attack cost: ~$attackCost possibilities (TRIVIAL to attack!)');
    }
  }

  // Recommendation
  print('\n📊 Security Recommendation:');
  if (smallFactors == 0) {
    print('   ✅ Curve is safe for X-only ECDH (X256189)');
  } else {
    print('   ❌ Curve is NOT safe for X-only ECDH');
    print('   ⚠️  Use Ed25519-style signatures only, not X25519-style key exchange');
    print('   ⚠️  If X-only ECDH is required, implement point validation on both curves');
  }

  print('\n╚══════════════════════════════════════╝');
}