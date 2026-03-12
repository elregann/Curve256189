import 'dart:typed_data';
import 'src/params.dart';
import 'src/field.dart';
import 'src/montgomery.dart';
import 'src/edwards.dart';
import 'src/eddsa.dart';

void main() {
  print("--- 🛡️ CURVE256189 DEEP DIAGNOSTIC AUDIT ---");
  print("Date: March 12, 2026\n");

  _testFieldInversion();
  _testMontgomeryToEdwardsConsistency();
  _traceLadderProblem();
  _testYRecoveryAmbiguity();
  _testEdDSASignatureConsistency();
  _diagnosticFinal();
  _diagnosticPrecisionTest();
  _testLadderLogicTrace();
  _diagnosticXRayDoubling();
  _finalCheckRootCause();
  _diagnosticConstantHunter();
  _diagnosticFormulaSniper();
}

void _testFieldInversion() {
  print("[AUDIT 1] Field Inversion Test");
  final a = BigInt.parse("12345678901234567890");
  final invA = FieldElement.inv(a);
  final product = FieldElement.mul(a, invA);
  print(product == BigInt.one ? "✅ PASS" : "❌ FAIL");
  print("");
}

void _testMontgomeryToEdwardsConsistency() {
  print("[AUDIT 2] Montgomery ↔ Edwards Consistency");
  final G_mont = MontgomeryPoint.G;
  final G_ed = TwistedEdwards.fromMontgomery(G_mont);
  final onCurve = TwistedEdwards.isOnCurve(G_ed);
  final G_back = TwistedEdwards.toMontgomery(G_ed);

  print("   On Curve Edwards: $onCurve");
  print("   Round-trip Match: ${G_back.x == G_mont.x}");
  print(onCurve && G_back.x == G_mont.x ? "✅ PASS" : "❌ FAIL");
  print("");
}

/// DIAGNOSTIK BARU: Mencari letak perbedaan X antara Affine dan Ladder
void _traceLadderProblem() {
  print("[DIAGNOSTIC] Tracing X-Coordinate Deviation");

  // Kita coba k = 2 dulu (Doubling)
  final k2 = BigInt.from(2);
  final R2_affine = Montgomery.double_(MontgomeryPoint.G);
  final R2_ladder_x = Montgomery.ladderXOnly(k2, MontgomeryPoint.G.x);

  print("   k=2 | Affine X: ${R2_affine.x}");
  print("   k=2 | Ladder X: $R2_ladder_x");

  if (R2_affine.x != R2_ladder_x) {
    print("   🚨 Error terdeteksi sejak Doubling (k=2)!");
  } else {
    // Jika k=2 aman, cek k=3 (Add + Double)
    final k3 = BigInt.from(3);
    final R3_affine = Montgomery.add(R2_affine, MontgomeryPoint.G);
    final R3_ladder_x = Montgomery.ladderXOnly(k3, MontgomeryPoint.G.x);

    print("   k=3 | Affine X: ${R3_affine.x}");
    print("   k=3 | Ladder X: $R3_ladder_x");

    if (R3_affine.x != R3_ladder_x) {
      print("   🚨 Error muncul saat bit-transition di k=3!");
    }
  }
  print("");
}

void _testYRecoveryAmbiguity() {
  print("[AUDIT 3] Y-Recovery Deep Investigation");
  final k = BigInt.from(5);

  // Reference (Affine)
  MontgomeryPoint R_affine = MontgomeryPoint.G;
  for (int i = 0; i < 4; i++) {
    R_affine = Montgomery.add(R_affine, MontgomeryPoint.G);
  }

  // Result (Ladder)
  final R_ladder = Montgomery.scalarMul(k, MontgomeryPoint.G);

  print("   Expected X: ${R_affine.x}");
  print("   Actual X  : ${R_ladder.x}");
  print("   Expected Y: ${R_affine.y}");
  print("   Actual Y  : ${R_ladder.y}");

  if (R_affine.x == R_ladder.x) {
    if (R_affine.y == R_ladder.y) {
      print("✅ PASS: Y-Recovery Match");
    } else if (FieldElement.sub(BigInt.zero, R_affine.y) == R_ladder.y) {
      print("⚠️ WARNING: Sign Flip (Y vs -Y)");
    } else {
      print("❌ FAIL: Y-Value Incorrect");
    }
  } else {
    print("❌ FAIL: X-Coordinate Mismatch");
  }
  print("");
}

void _testEdDSASignatureConsistency() {
  print("[AUDIT 4] EdDSA Signature Integrity");
  final seed = Uint8List.fromList(List.generate(32, (i) => i));
  final message = Uint8List.fromList([1, 2, 3, 4, 5]);

  try {
    final keys = EdDSA.generateKeyPair(seed);
    final sig = EdDSA.sign(message, keys['privateKey']!);
    final isValid = EdDSA.verify(message, sig, keys['publicKey']!);
    print(isValid ? "✅ PASS" : "❌ FAIL");
  } catch (e) {
    print("💥 CRASH: $e");
  }
  print("");
}

/// DIAGNOSTIK FINAL: Bedah A24 dan Manual Doubling
void _diagnosticFinal() {
  print("[DIAGNOSTIC] Deep Dive: Doubling & a24");

  final xP = Curve256189Params.gx;
  final affineX2 = Montgomery.double_(MontgomeryPoint.G).x;

  // Pakai rumus primal langsung
  final x2 = FieldElement.mul(xP, xP);
  final Ax = FieldElement.mul(Curve256189Params.A, xP);

  final numerator = FieldElement.mul(
      FieldElement.sub(x2, BigInt.one),
      FieldElement.sub(x2, BigInt.one)
  );

  final denominator = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), xP),
      FieldElement.add(FieldElement.add(x2, Ax), BigInt.one)
  );

  final finalX = FieldElement.mul(numerator, FieldElement.inv(denominator));

  print("   Manual Projective X: $finalX");
  print("   Affine Doubling X  : $affineX2");

  if (finalX == affineX2) {
    print("✅ Doubling Logic is Correct!");
  } else {
    print("❌ Doubling Logic is Broken!");
  }
  print("");
}

void _diagnosticPrecisionTest() {
  print("[DIAGNOSTIC] Precision Isolation Test");

  final A = Curve256189Params.A;
  final xP = Curve256189Params.gx;
  final target_affine = Montgomery.double_(MontgomeryPoint.G).x;

  // Rumus primal
  final x2 = FieldElement.mul(xP, xP);
  final Ax = FieldElement.mul(A, xP);

  final numerator = FieldElement.mul(
      FieldElement.sub(x2, BigInt.one),
      FieldElement.sub(x2, BigInt.one)
  );

  final denominator = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), xP),
      FieldElement.add(FieldElement.add(x2, Ax), BigInt.one)
  );

  final res = FieldElement.mul(numerator, FieldElement.inv(denominator));

  print("   Hasil Rumus Primal: $res");
  print("   Target Affine X   : $target_affine");

  if (res == target_affine) {
    print("✅ KONFIRMASI: Rumus Primal benar!");
  } else {
    print("❌ RUMUS PRIMAL GAGAL!");
  }
  print("");
}

// --- FUNGSI PEMBANTU UNTUK DIAGNOSTIK (Salin ke bagian bawah file audit) ---

List<BigInt> localXDBL(BigInt X, BigInt Z) {
  final BigInt A = Curve256189Params.A;

  final BigInt X2 = FieldElement.mul(X, X);
  final BigInt Z2 = FieldElement.mul(Z, Z);
  final BigInt XZ = FieldElement.mul(X, Z);

  final BigInt X3 = FieldElement.mul(
      FieldElement.sub(X2, Z2),
      FieldElement.sub(X2, Z2)
  );

  final BigInt temp = FieldElement.add(
      FieldElement.add(X2, FieldElement.mul(A, XZ)),
      Z2
  );
  final BigInt Z3 = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), XZ),
      temp
  );

  return [X3, Z3];
}

List<BigInt> localXADD(BigInt Xp, BigInt Zp, BigInt Xq, BigInt Zq, BigInt x) {
  final BigInt U = FieldElement.mul(
      FieldElement.sub(Xp, Zp),
      FieldElement.add(Xq, Zq)
  );
  final BigInt V = FieldElement.mul(
      FieldElement.add(Xp, Zp),
      FieldElement.sub(Xq, Zq)
  );
  final BigInt add = FieldElement.add(U, V);
  final BigInt sub = FieldElement.sub(U, V);
  final BigInt Xr = FieldElement.mul(add, add);
  final BigInt Zr = FieldElement.mul(x, FieldElement.mul(sub, sub));
  return [Xr, Zr];
}

// --- FUNGSI TEST UTAMA ---

void _testLadderLogicTrace() {
  print("[DIAGNOSTIC] Ladder Initialization & Loop Trace");

  final k = BigInt.from(5); // Kita coba k=5 (101 dalam biner)
  final xP = Curve256189Params.gx;

  // 1. Logika Kapten: Mulai dari bitLen-1 (bit 1 pertama diproses)
  BigInt testCurrentLadder(BigInt k, BigInt xP) {
    BigInt x0 = BigInt.one; BigInt z0 = BigInt.zero; // R0 = Infinity
    BigInt x1 = xP; BigInt z1 = BigInt.one;         // R1 = P
    final int bitLen = k.bitLength;
    for (int i = bitLen - 1; i >= 0; i--) {
      final bit = (k >> i) & BigInt.one;
      if (bit == BigInt.zero) {
        var add = localXADD(x0, z0, x1, z1, xP);
        var dbl = localXDBL(x0, z0);
        x1 = add[0]; z1 = add[1]; x0 = dbl[0]; z0 = dbl[1];
      } else {
        var add = localXADD(x0, z0, x1, z1, xP);
        var dbl = localXDBL(x1, z1);
        x0 = add[0]; z0 = add[1]; x1 = dbl[0]; z1 = dbl[1];
      }
    }
    return FieldElement.mul(x0, FieldElement.inv(z0));
  }

  // 2. Logika Alternatif: Bit pertama dipakai untuk inisialisasi, loop mulai dari bit ke-2
  BigInt testFixedLadder(BigInt k, BigInt xP) {
    // Inisialisasi: R0 = P, R1 = 2P
    BigInt x0 = xP;
    BigInt z0 = BigInt.one;
    var dblInitial = localXDBL(xP, BigInt.one);
    BigInt x1 = dblInitial[0];
    BigInt z1 = dblInitial[1];

    final int bitLen = k.bitLength;
    // Loop mulai dari bitLen - 2
    for (int i = bitLen - 2; i >= 0; i--) {
      final bit = (k >> i) & BigInt.one;
      if (bit == BigInt.zero) {
        var add = localXADD(x0, z0, x1, z1, xP);
        var dbl = localXDBL(x0, z0);
        x1 = add[0]; z1 = add[1]; x0 = dbl[0]; z0 = dbl[1];
      } else {
        var add = localXADD(x0, z0, x1, z1, xP);
        var dbl = localXDBL(x1, z1);
        x0 = add[0]; z0 = add[1]; x1 = dbl[0]; z1 = dbl[1];
      }
    }
    return FieldElement.mul(x0, FieldElement.inv(z0));
  }

  // 3. Referensi Affine (G+G+G+G+G)
  MontgomeryPoint R_affine = MontgomeryPoint.G;
  for (int i = 0; i < 4; i++) {
    R_affine = Montgomery.add(R_affine, MontgomeryPoint.G);
  }

  final resA = testCurrentLadder(k, xP);
  final resB = testFixedLadder(k, xP);

  print("   Current Loop (resA): $resA");
  print("   Fixed Loop   (resB): $resB");
  print("   Target Affine (5G) : ${R_affine.x}");

  if (resB == R_affine.x) {
    print("✅ KONFIRMASI: Ladder harus melewati bit pertama!");
  } else if (resA == R_affine.x) {
    print("✅ KONFIRMASI: Logika loop bit pertama sudah benar, masalah di tempat lain.");
  } else {
    print("❌ Keduanya masih belum cocok dengan Affine.");
  }
}

void _diagnosticXRayDoubling() {
  print("[DIAGNOSTIC] X-Ray: Stepping through Doubling");

  final A = Curve256189Params.A;
  final xP = Curve256189Params.gx;
  final target = Montgomery.double_(MontgomeryPoint.G).x;

  // Rumus primal step by step
  final x2 = FieldElement.mul(xP, xP);
  final Ax = FieldElement.mul(A, xP);

  final numerator = FieldElement.mul(
      FieldElement.sub(x2, BigInt.one),
      FieldElement.sub(x2, BigInt.one)
  );

  final denominator = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), xP),
      FieldElement.add(FieldElement.add(x2, Ax), BigInt.one)
  );

  final finalX = FieldElement.mul(numerator, FieldElement.inv(denominator));

  print("   Result X      : $finalX");
  print("   Target Affine : $target");

  if (finalX == target) {
    print("✅ RUMUS COCOK!");
  } else {
    print("❌ RUMUS MASIH SALAH!");
  }
}

void _finalCheckRootCause() {
  print("[DIAGNOSTIC] Final Verification: Projective Doubling Fix");

  final A = Curve256189Params.A;
  final xP = Curve256189Params.gx;
  final target = Montgomery.double_(MontgomeryPoint.G).x;

  final x2 = FieldElement.mul(xP, xP);
  final Ax = FieldElement.mul(A, xP);

  final numerator = FieldElement.mul(
      FieldElement.sub(x2, BigInt.one),
      FieldElement.sub(x2, BigInt.one)
  );

  final denominator = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), xP),
      FieldElement.add(FieldElement.add(x2, Ax), BigInt.one)
  );

  final resX = FieldElement.mul(numerator, FieldElement.inv(denominator));

  print("   New Projective Result: $resX");
  print("   Target Affine Result : $target");

  if (resX == target) {
    print("✅ AKAR MASALAH DITEMUKAN!");
  } else {
    print("❌ Masih Mismatch.");
  }
}

void _diagnosticConstantHunter() {
  print("[DIAGNOSTIC] Constant Hunter: Verifying A");

  final xP = Curve256189Params.gx;
  final targetX = Montgomery.double_(MontgomeryPoint.G).x;
  final A = Curve256189Params.A;

  final x2 = FieldElement.mul(xP, xP);
  final Ax = FieldElement.mul(A, xP);

  final numerator = FieldElement.mul(
      FieldElement.sub(x2, BigInt.one),
      FieldElement.sub(x2, BigInt.one)
  );

  final denominator = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), xP),
      FieldElement.add(FieldElement.add(x2, Ax), BigInt.one)
  );

  final resX = FieldElement.mul(numerator, FieldElement.inv(denominator));

  print("   Original A : $A");
  print("   Hasil dengan A tersebut: $resX");
  print("   Target Affine          : $targetX");

  if (resX == targetX) {
    print("✅ A sudah benar!");
  } else {
    print("❌ A bermasalah.");
  }
}

void _diagnosticFormulaSniper() {
  print("[DIAGNOSTIC] Formula Sniper: Primal Doubling Test");

  final A = Curve256189Params.A;
  final xP = Curve256189Params.gx;
  final targetX = BigInt.parse("74734243360051852690793025925459525207778181253256383644632050803113799752244");

  // RUMUS PRIMAL (Tanpa Optimasi)
  // X2 = (x² - 1)²
  // Z2 = 4x(x² + Ax + 1)

  final x2 = FieldElement.mul(xP, xP);
  final x_plus_1 = FieldElement.add(x2, BigInt.one);
  final Ax = FieldElement.mul(A, xP);

  final numerator = FieldElement.mul(
      FieldElement.sub(x2, BigInt.one),
      FieldElement.sub(x2, BigInt.one)
  );

  final denominator = FieldElement.mul(
      FieldElement.mul(BigInt.from(4), xP),
      FieldElement.add(x_plus_1, Ax)
  );

  final resX = FieldElement.mul(numerator, FieldElement.inv(denominator));

  print("   Primal Projective Result: $resX");
  print("   Target Affine Result   : $targetX");

  if (resX == targetX) {
    print("✅ RUMUS PRIMAL BERHASIL!");
    print("👉 Ini artinya: Struktur Ladder (U, V, W) Kapten yang punya typo logika.");
  } else {
    print("❌ BAHAYA: Rumus Primal pun gagal. Ada masalah di level FieldElement!");
  }
}