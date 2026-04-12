// test_compression.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Point Compression and Decompression ===');
  print('');

  // Test case 1: Encode G, then decode it. The result should match the original point.
  final G_mont = MontgomeryPoint.G;
  final G_ed = TwistedEdwards.fromMontgomery(G_mont);

  print('Test 1 - Encode G:');
  final encoded = TwistedEdwards.encodePoint(G_ed);
  print('  Encoded: ${encoded.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Length: ${encoded.length} bytes');
  print('');

  print('Test 2 - Decode G:');
  final decoded = TwistedEdwards.decodePoint(encoded);
  print('  Decoded x: ${decoded?.x}');
  print('  Decoded y: ${decoded?.y}');
  print('  x equal? ${decoded?.x == G_ed.x}');
  print('  y equal? ${decoded?.y == G_ed.y}');
  print('');

  // Test case 3: Verify that the decoded point lies on the curve.
  print('Test 3 - Is decoded G on the curve?');
  print('  isOnCurve: ${TwistedEdwards.isOnCurve(decoded!)}');
  print('');

  // Test case 4: Encode and decode random points (2G, 4G).
  final G2 = TwistedEdwards.add(G_ed, G_ed);
  final encoded2G = TwistedEdwards.encodePoint(G2);
  final decoded2G = TwistedEdwards.decodePoint(encoded2G);
  print('Test 4 - Encode and decode 2G:');
  print('  x equal? ${decoded2G?.x == G2.x}');
  print('  y equal? ${decoded2G?.y == G2.y}');
  print('');

  print('=== All Tests Completed ===');
}