// test_timing.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test Constant-Time Scalar Multiplication ===\n');

  final G_ed = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);
  final n = Curve256189Params.n;

  // Test 1: Correctness — n*G == titik netral (0,1)?
  print('Test 1 - n*G == titik netral (0,1)?');
  final nG = TwistedEdwards.scalarMul(n, G_ed);
  print('  n*G.x = ${nG.x}');
  print('  n*G.y = ${nG.y}');
  print('  Valid? ${nG.x == BigInt.zero && nG.y == BigInt.one}\n');

  // Test 2: Correctness — 1*G == G?
  print('Test 2 - 1*G == G?');
  final oneG = TwistedEdwards.scalarMul(BigInt.one, G_ed);
  print('  Valid? ${oneG.x == G_ed.x && oneG.y == G_ed.y}\n');

  // Test 3: Correctness — 2*G == G+G?
  print('Test 3 - 2*G == G+G?');
  final twoG = TwistedEdwards.scalarMul(BigInt.two, G_ed);
  final GplusG = TwistedEdwards.add(G_ed, G_ed);
  print('  Valid? ${twoG.x == GplusG.x && twoG.y == GplusG.y}\n');

  // Test 4: Timing — scalar dengan banyak bit 0
  final scalarAllZero = BigInt.parse(
      '100000000000000000000000000000000000000000000000000000000000000000', radix: 16
  );

  // Test 5: Timing — scalar dengan banyak bit 1
  final scalarAllOne = BigInt.parse(
      '1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', radix: 16
  );

  print('Test 4 - Timing comparison:');

  final sw1 = Stopwatch()..start();
  for (int i = 0; i < 5; i++) {
    TwistedEdwards.scalarMul(scalarAllZero, G_ed);
  }
  sw1.stop();
  final time0 = sw1.elapsedMilliseconds;

  final sw2 = Stopwatch()..start();
  for (int i = 0; i < 5; i++) {
    TwistedEdwards.scalarMul(scalarAllOne, G_ed);
  }
  sw2.stop();
  final time1 = sw2.elapsedMilliseconds;

  print('  Waktu scalar banyak 0: ${time0}ms (5x)');
  print('  Waktu scalar banyak 1: ${time1}ms (5x)');
  print('  Selisih: ${(time0 - time1).abs()}ms');
  print('  Timing konsisten? ${(time0 - time1).abs() < 500}\n');

  // Test 5: Jalankan EdDSA sign+verify masih benar?
  print('Test 5 - EdDSA masih valid setelah Montgomery Ladder?');
  print('  (Jalankan test_eddsa.dart untuk konfirmasi)\n');

  print('=== Semua Test Selesai ===');
}