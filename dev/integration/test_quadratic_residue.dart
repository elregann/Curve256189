// test_quadratic_residue.dart

// Quadratic residue distribution test for Curve256189
//
// For p ≡ 3 (mod 4), the square root formula x = a^((p+1)/4) works.
// This test verifies that approximately 50% of small integers
// are quadratic residues, which is expected by number theory.

import 'package:curve256189/curve256189.dart';

void main() {
  print('Quadratic Residue Test');
  print('');

  final p = Curve256189Params.p;
  final exp = (p + BigInt.one) >> 2;  // Exponent for square root computation when p ≡ 3 mod 4

  print('Curve parameters:');
  print('  p = $p');
  print('  p mod 4 = ${p % BigInt.from(4)}');
  print('  exp = (p + 1) / 4 = $exp');
  print('');

  const int total = 100;
  int residues = 0;

  print('Testing the first $total integers:');
  print('');

  for (int i = 1; i <= total; i++) {
    final x2 = BigInt.from(i);
    final sqrt = x2.modPow(exp, p);
    final isResidue = (sqrt * sqrt) % p == x2;

    if (isResidue) {
      residues++;
      print('  $x2 is a quadratic residue');
    } else {
      print('  $x2 is NOT a quadratic residue');
    }
  }

  final percentage = (residues / total * 100).toStringAsFixed(1);
  print('');
  print('Results:');
  print('  Residues: $residues/$total = $percentage%');
  print('  Expected: approximately 50% for a random distribution');

  if (residues > 40 && residues < 60) {
    print('  PASS: Distribution is within the expected range.');
  } else {
    print('  WARNING: Distribution deviates from the expected 50%.');
  }

  print('');
  print('=== Quadratic Residue Test Completed ===');
}