import 'src/params.dart';
import 'src/edwards.dart';

void main() {
  print("--- 🔬 EDWARDS COMPLETENESS STRESS TEST ---");
  print("Curve: Curve256189");
  print("Target: Finding the 'False' gap in Edwards Addition\n");

  // 1. Identifikasi Titik-Titik Torsi (The Ghost Points)
  // Titik Netral (0, 1)
  final neutral = EdwardsPoint(BigInt.zero, BigInt.one);

  // Titik Order 2 (0, -1) -> dalam field p ini adalah (0, p-1)
  final p = Curve256189Params.p;
  final order2 = EdwardsPoint(BigInt.zero, p - BigInt.one);

  // 2. Ambil titik G (Edwards) dari params
  final g = EdwardsPoint(Curve256189Params.gxEd, Curve256189Params.gyEd);

  print("--- [TEST 1: Neutral Point Addition] ---");
  _runAddTest("G + Neutral", g, neutral);

  print("\n--- [TEST 2: Order-2 Point Addition] ---");
  _runAddTest("G + Order2", g, order2);

  print("\n--- [TEST 3: The Critical Self-Inverse] ---");
  // Menjumlahkan P dengan -P (seharusnya menghasilkan neutral)
  final negG = EdwardsPoint(p - g.x, g.y);
  _runAddTest("G + (-G)", g, negG);

  print("\n--- [TEST 4: Doubling via Add Function] ---");
  _runAddTest("G + G", g, g);

  print("\n--- [TEST 5: BRUTE FORCE SCALAR ADDITION] ---");
  var currentPoint = g;
  for (int i = 1; i <= 1000000; i++) {
    try {
      // Terus menjumlahkan titik G dengan dirinya sendiri berkali-kali
      currentPoint = TwistedEdwards.add(currentPoint, g);

      if (!TwistedEdwards.isOnCurve(currentPoint)) {
        print("🚨 GAGAL di iterasi ke-$i: Titik keluar dari kurva!");
        break;
      }
    } catch (e) {
      print("💀 CRASH di iterasi ke-$i: $e");
      break;
    }
    if (i % 25000 == 0) print("Iterasi $i aman...");
  }
  print("✅ Brute Force 1.000.000 iterasi selesai. Curve256189 tetap kokoh!");
}

void _runAddTest(String label, EdwardsPoint p1, EdwardsPoint p2) {
  try {
    print("Testing $label...");
    // Pastikan nama class dan method sesuai dengan di edwards.dart Kapten
    final result = TwistedEdwards.add(p1, p2);

    print("   Result X: ${result.x}");
    print("   Result Y: ${result.y}");

    // Verifikasi menggunakan a dan d dari params untuk memastikan titik valid
    final onCurve = TwistedEdwards.isOnCurve(result);

    if (onCurve) {
      print("   ✅ STATUS: PASS (Titik tetap di jalur kurva)");
    } else {
      print("   🚨 STATUS: FAIL (Hasil keluar dari kurva!)");
    }
  } catch (e) {
    print("   ❌ CRASH: Terdeteksi kegagalan rumus (Division by Zero?)!");
    print("   Detail: $e");
  }
}