// test_quadratic_residue.dart
// Quadratic residue distribution test for Curve256189
//
// For p ≡ 3 (mod 4), the square root formula x = a^((p+1)/4) works.
// This test verifies that approximately 50% of small integers
// are quadratic residues, which is expected by number theory.

import 'package:curve256189/curve256189.dart';

void main() {
  print('╔══════════════════════════════════════╗');
  print('║  Quadratic Residue Test              ║');
  print('╚══════════════════════════════════════╝');

  final p = Curve256189Params.p;
  final exp = (p + BigInt.one) >> 2;

  print('\n📊 Curve parameters:');
  print('  p = $p');
  print('  p mod 4 = ${p % BigInt.from(4)}');
  print('  exp = (p+1)/4 = $exp\n');

  const int total = 100;
  int residues = 0;

  print('📋 Testing first $total integers:');
  print('   ${"-" * 40}');

  for (int i = 1; i <= total; i++) {
    final x2 = BigInt.from(i);
    final sqrt = x2.modPow(exp, p);
    final isResidue = (sqrt * sqrt) % p == x2;

    if (isResidue) {
      residues++;
      print('  ✅ $x2 is quadratic residue');
    } else {
      print('  ❌ $x2 is NOT quadratic residue');
    }
  }

  final percentage = (residues / total * 100).toStringAsFixed(1);
  print('\n📊 Results:');
  print('  Residues: $residues/$total = $percentage%');
  print('  Expected: ~50% for random distribution');

  if (residues > 40 && residues < 60) {
    print('  ✅ PASS — Distribution within expected range');
  } else {
    print('  ⚠️  WARNING — Distribution deviates from expected 50%');
  }

  print('\n╚══════════════════════════════════════╝');
}