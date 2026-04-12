// test_hfe.dart

import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  // Test case: Use a fixed seed for deterministic constant derivation.
  final seed = Uint8List.fromList(List.generate(32, (i) => i + 1));

  // Derive constants from the seed.
  final constants = HFE.deriveConstants(seed);
  final a = constants['a']!;
  final b = constants['b']!;
  final c = constants['c']!;
  final d = constants['d']!;
  final coeff = constants['coeff']!;

  print('=== Test: HFE Curve256189 ===');
  print('a     = $a');
  print('coeff = $coeff');

  // Test case 1: Verify the wrap function produces a valid scalar.
  final k = BigInt.from(999);
  final kPrime = HFE.wrap(k, a, b, c, d, coeff);
  print('');
  print('k       = $k');
  print('k prime = $kPrime');
  print('k prime valid? ${kPrime > BigInt.zero && kPrime < HFE.n}');

  // Test case 2: Verify that wrap is deterministic (same input produces same output).
  final kPrime2 = HFE.wrap(k, a, b, c, d, coeff);
  print('Deterministic? ${kPrime == kPrime2}');

  // Test case 3: Verify that different inputs produce different outputs.
  final kPrime3 = HFE.wrap(BigInt.from(1000), a, b, c, d, coeff);
  print('Different input produces different output? ${kPrime != kPrime3}');
}