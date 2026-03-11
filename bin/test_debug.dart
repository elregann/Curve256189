// test_debug.dart
import 'edwards.dart';
import 'montgomery.dart';

void main() {
  final G = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);
  print('G_ed.x = ${G.x}');
  print('G_ed.y = ${G.y}');

  // Convert balik ke Montgomery
  final G_mont = TwistedEdwards.toMontgomery(G);
  print('G_mont.x = ${G_mont.x}');
  print('G_mont.y = ${G_mont.y}');
  print('G_mont == G? ${G_mont.x == MontgomeryPoint.G.x && G_mont.y == MontgomeryPoint.G.y}');

  // scalarMulDebug vs scalarMul
  final k = BigInt.from(3);
  final r1 = TwistedEdwards.scalarMul(k, G);
  final r2 = TwistedEdwards.scalarMulDebug(k, G);
  print('scalarMul 3G.x    = ${r1.x}');
  print('scalarMulDebug 3G.x = ${r2.x}');
  print('sama? ${r1.x == r2.x && r1.y == r2.y}');
}