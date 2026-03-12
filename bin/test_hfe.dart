import 'dart:typed_data';
import 'hfe.dart';

void main() {
  // Seed test
  final seed = Uint8List.fromList(List.generate(32, (i) => i + 1));

  // Derive constants
  final constants = HFE.deriveConstants(seed);
  final a = constants['a']!;
  final b = constants['b']!;
  final c = constants['c']!;
  final d = constants['d']!;
  final coeff = constants['coeff']!;

  print('=== Test HFE Curve256189 ===');
  print('a     = $a');
  print('coeff = $coeff');

  // Test wrap
  final k = BigInt.from(999);
  final kPrime = HFE.wrap(k, a, b, c, d, coeff);
  print('\nk       = $k');
  print('k prime = $kPrime');
  print('k prime valid? ${kPrime > BigInt.zero && kPrime < HFE.n}');

  // Test deterministik
  final kPrime2 = HFE.wrap(k, a, b, c, d, coeff);
  print('Deterministik? ${kPrime == kPrime2}');

  // Test berbeda input → berbeda output
  final kPrime3 = HFE.wrap(BigInt.from(1000), a, b, c, d, coeff);
  print('Berbeda input → berbeda output? ${kPrime != kPrime3}');
}