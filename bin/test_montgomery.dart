import 'montgomery.dart';
import 'params.dart';

void main() {
  print('=== Test Montgomery Operations ===\n');

  // Test 1: Base point on curve?
  final G = MontgomeryPoint.G;
  print('Test 1 - Base Point on curve?');
  print('  isOnCurve(G): ${Montgomery.isOnCurve(G)}\n');

  // Test 2: Point doubling
  final G2 = Montgomery.double_(G);
  print('Test 2 - Point Doubling (2G):');
  print('  2G.x = ${G2.x}');
  print('  2G.y = ${G2.y}');
  print('  isOnCurve(2G): ${Montgomery.isOnCurve(G2)}\n');

  // Test 3: Point addition (G + G == 2G?)
  final GplusG = Montgomery.add(G, G);
  print('Test 3 - Point Addition (G + G == 2G?):');
  print('  G + G == 2G? ${GplusG.x == G2.x && GplusG.y == G2.y}\n');

  // Test 4: Scalar multiplication
  final G4 = Montgomery.scalarMul(BigInt.from(4), G);
  print('Test 4 - Scalar Multiplication (4G):');
  print('  4G.x = ${G4.x}');
  print('  4G.y = ${G4.y}');
  print('  isOnCurve(4G): ${Montgomery.isOnCurve(G4)}\n');

  // Test 5: n*G == infinity?
  final n = Curve256189Params.n;
  final nG = Montgomery.scalarMul(n, G);
  print('Test 5 - n*G == infinity?');
  print('  n*G isInfinity: ${nG.isInfinity}\n');

  // Test 6: infinity + G == G?
  final inf = MontgomeryPoint.infinity();
  final infPlusG = Montgomery.add(inf, G);
  print('Test 6 - Infinity + G == G?');
  print('  result == G? ${infPlusG.x == G.x && infPlusG.y == G.y}\n');

  print('=== Semua Test Selesai ===');
}