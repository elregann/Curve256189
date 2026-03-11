import 'edwards.dart';
import 'montgomery.dart';
import 'params.dart';

void main() {
  print('=== Test Twisted Edwards Operations ===\n');

  // Test 1: Cek parameter a dan d
  print('Test 1 - Parameter Twisted Edwards:');
  print('  a = ${TwistedEdwards.a}');
  print('  d = ${TwistedEdwards.d}\n');

  // Test 2: Konversi G dari Montgomery ke Edwards
  final G_mont = MontgomeryPoint.G;
  final G_ed = TwistedEdwards.fromMontgomery(G_mont);
  print('Test 2 - Konversi Base Point G (Montgomery → Edwards):');
  print('  G_ed.x = ${G_ed.x}');
  print('  G_ed.y = ${G_ed.y}\n');

  // Test 3: G hasil konversi on curve?
  print('Test 3 - G Edwards on curve?');
  print('  isOnCurve(G_ed): ${TwistedEdwards.isOnCurve(G_ed)}\n');

  // Test 4: Point addition (G + G == 2G?)
  final G2_ed = TwistedEdwards.add(G_ed, G_ed);
  final G2_mont = TwistedEdwards.fromMontgomery(
    Montgomery.double_(G_mont),
  );
  print('Test 4 - G_ed + G_ed == 2G (dari Montgomery)?');
  print('  G_ed + G_ed == 2G? ${G2_ed.x == G2_mont.x && G2_ed.y == G2_mont.y}\n');

  // Test 5: Scalar multiplication n*G == titik netral (0,1)?
  final n = Curve256189Params.n;
  final nG_ed = TwistedEdwards.scalarMul(n, G_ed);
  print('Test 5 - n*G == titik netral (0, 1)?');
  print('  n*G.x = ${nG_ed.x}');
  print('  n*G.y = ${nG_ed.y}');
  print('  n*G == (0,1)? ${nG_ed.x == BigInt.zero && nG_ed.y == BigInt.one}\n');

  print('=== Semua Test Selesai ===');
}