// test_debug.dart
import 'edwards.dart';
import 'montgomery.dart';

void main() {
  final G = TwistedEdwards.fromMontgomery(MontgomeryPoint.G);

  // Round-trip test
  final G_mont = TwistedEdwards.toMontgomery(G);
  print('G round-trip ok? ${G_mont.x == MontgomeryPoint.G.x}');

  // scalarMul correctness via Montgomery x
  final s3G = TwistedEdwards.scalarMul(BigInt.from(3), G);
  final s4G = TwistedEdwards.scalarMul(BigInt.from(4), G);
  final a4G = Montgomery.add(Montgomery.double_(MontgomeryPoint.G), Montgomery.double_(MontgomeryPoint.G));

  print('3G on curve? ${TwistedEdwards.isOnCurve(s3G)}');
  print('4G on curve? ${TwistedEdwards.isOnCurve(s4G)}');
  print('scalarMul(3G) mont.x = ${TwistedEdwards.toMontgomery(s3G).x}');
  print('scalarMul(4G) mont.x = ${TwistedEdwards.toMontgomery(s4G).x}');
  print('affine 4G mont.x     = ${a4G.x}');
  print('4G match? ${TwistedEdwards.toMontgomery(s4G).x == a4G.x}');
}