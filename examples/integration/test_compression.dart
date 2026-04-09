// test_compression.dart

import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test Point Compression & Decompression ===\n');

  // Test 1: Encode lalu decode G — hasilnya harus sama
  final G_mont = MontgomeryPoint.G;
  final G_ed = TwistedEdwards.fromMontgomery(G_mont);

  print('Test 1 - Encode G:');
  final encoded = TwistedEdwards.encodePoint(G_ed);
  print('  Encoded: ${encoded.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('  Length: ${encoded.length} bytes\n');

  print('Test 2 - Decode G:');
  final decoded = TwistedEdwards.decodePoint(encoded);
  print('  Decoded x: ${decoded?.x}');
  print('  Decoded y: ${decoded?.y}');
  print('  x sama? ${decoded?.x == G_ed.x}');
  print('  y sama? ${decoded?.y == G_ed.y}\n');

  // Test 3: isOnCurve setelah decode?
  print('Test 3 - Decoded G on curve?');
  print('  isOnCurve: ${TwistedEdwards.isOnCurve(decoded!)}\n');

  // Test 4: Encode decode titik acak (2G, 4G)
  final G2 = TwistedEdwards.add(G_ed, G_ed);
  final encoded2G = TwistedEdwards.encodePoint(G2);
  final decoded2G = TwistedEdwards.decodePoint(encoded2G);
  print('Test 4 - Encode/Decode 2G:');
  print('  x sama? ${decoded2G?.x == G2.x}');
  print('  y sama? ${decoded2G?.y == G2.y}\n');

  print('=== Semua Test Selesai ===');
}