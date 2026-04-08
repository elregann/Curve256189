// test_elligator.dart
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test Elligator 2 Curve256189 ===');

  // Test 1: encode menghasilkan x yang valid
  print('\nTest 1 - Encode t → x on curve?');
  for (final t in [1, 2, 3, 100, 999]) {
    final x = Elligator.encode(BigInt.from(t));
    print('  t=$t → x valid? ${x != null}');
  }

  // Test 2: round-trip x konsisten
  print('\nTest 2 - Round-trip x konsisten?');
  for (final t in [1, 2, 3, 100, 999]) {
    final x1 = Elligator.encode(BigInt.from(t));
    if (x1 == null) continue;
    final tBack = Elligator.decode(x1);
    if (tBack == null) continue;
    final x2 = Elligator.encode(tBack);
    print('  t=$t → x match? ${x1 == x2}');
  }

  // Test 3: t=0 return null
  print('\nTest 3 - t=0 return null?');
  print('  ${Elligator.encode(BigInt.zero) == null}');

  // Test 4: output tidak khas ECC
  print('\nTest 4 - Output tidak khas ECC?');
  final x = Elligator.encode(BigInt.from(42));
  print('  x = $x');

  // Test 5: ~50% titik tidak bisa di-decode
  print('\nTest 5 - ~50% x tidak punya representasi Elligator?');
  int canDecode = 0;
  int cannot = 0;
  for (int i = 1; i <= 100; i++) {
    // Buat x valid di kurva via encode
    final x = Elligator.encode(BigInt.from(i));
    if (x == null) continue;
    // Coba decode x yang sedikit dimodifikasi
    final xMod = x + BigInt.from(i * 7);
    final t = Elligator.decode(xMod);
    if (t != null) canDecode++;
    else cannot++;
  }
  print('  bisa decode: $canDecode');
  print('  tidak bisa:  $cannot');
  print('  ~50%? ${canDecode > 20 && cannot > 20}');

  // Test 6: encode selalu menghasilkan x on curve
  print('\nTest 6 - encode random t selalu on curve?');
  bool allOnCurve = true;
  final p = Curve256189Params.p;
  final A = Curve256189Params.A;
  for (int i = 1; i <= 50; i++) {
    final t = BigInt.from(i * 12345678);
    final x = Elligator.encode(t);
    if (x == null) continue;
    // Verify on curve: rhs = x³ + Ax² + x harus square
    final x2 = (x * x) % p;
    final x3 = (x * x2) % p;
    final rhs = (x3 + A * x2 + x) % p;
    final exp = (p + BigInt.one) >> 2;
    final y = rhs.modPow(exp, p);
    if ((y * y) % p != rhs) { allOnCurve = false; break; }
  }
  print('  semua on curve? $allOnCurve');

  // Test 7: t=0 edge case per RFC
  print('\nTest 7 - RFC edge case t=0?');
  print('  encode(0) == null? ${Elligator.encode(BigInt.zero) == null}');
}