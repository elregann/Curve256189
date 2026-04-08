// test_blinding.dart
// import 'src/montgomery.dart';
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test Scalar Blinding Curve256189 ===');

  final G = MontgomeryPoint.G;

  // Test 1: k*G == k_blind*G?
  print('\nTest 1 - Hasil sama dengan blinding?');
  final k = BigInt.parse('12345678901234567890');
  final x1 = Montgomery.ladderXOnly(k, G.x);
  final x2 = Montgomery.ladderXOnly(k, G.x);
  final x3 = Montgomery.ladderXOnly(k, G.x);
  print('  run 1 = $x1');
  print('  run 2 = $x2');
  print('  run 3 = $x3');
  print('  semua sama? ${x1 == x2 && x2 == x3}');

  // Test 2: timing berbeda setiap run (blinding aktif)?
  print('\nTest 2 - Blinding aktif (r berbeda setiap run)?');
  final r1 = Montgomery.blindScalar(k, BigInt.from(1));
  final r2 = Montgomery.blindScalar(k, BigInt.from(2));
  print('  k + 1*n = $r1');
  print('  k + 2*n = $r2');
  print('  r1 != r2? ${r1 != r2}');

  // Test 3: n*G masih infinity setelah blinding?
  print('\nTest 3 - n*G masih infinity?');
  final nG = Montgomery.ladderXOnly(Curve256189Params.n, G.x);
  print('  n*G.x = $nG');
  print('  infinity? ${nG == BigInt.zero}');

  // Test 4: isValidPoint masih bekerja?
  print('\nTest 4 - isValidPoint masih bekerja?');
  final kG = Montgomery.scalarMul(k, G);
  print('  k*G valid? ${Montgomery.isValidPoint(kG)}');
}