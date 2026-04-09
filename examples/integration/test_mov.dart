// test_mov.dart

// MOV Attack Vulnerability Test for Curve256189
//
// MOV (Menezes-Okamoto-Vanstone) attack reduces ECDLP to DLP in GF(p^k)
// when the embedding degree k is small. For secure curves, k must be large
// (typically > (log p)/8 ≈ 32 for 256-bit curves).

import 'package:curve256189/curve256189.dart';

void main() {
  print('╔══════════════════════════════════════╗');
  print('║  Curve256189 MOV Attack Test         ║');
  print('╚══════════════════════════════════════╝');

  final p = Curve256189Params.p;  // Field characteristic
  final n = Curve256189Params.n;  // Curve order

  print('\n📊 Parameters:');
  print('   p (field characteristic) = $p');
  print('   n (curve order)          = $n');

  // Check if p ≡ 1 mod n (trivial case)
  if (p % n == BigInt.one) {
    print('\n⚠️  p ≡ 1 mod n — embedding degree k = 1');
    print('   Curve is completely INSECURE against MOV attack!');
    return;
  }

  const maxK = 50;
  print('\n📊 Searching for embedding degree k ≤ $maxK...');
  print('   (p^k ≡ 1 mod n)');

  BigInt pk = p % n;
  int? foundK;

  for (int k = 1; k <= maxK; k++) {
    if (pk == BigInt.one) {
      foundK = k;
      break;
    }
    pk = (pk * p) % n;
  }

  // Results
  print('\n📊 MOV Analysis Results:');

  if (foundK != null) {
    print('   ⚠️  VULNERABLE — embedding degree k = $foundK');
    print('   ⚠️  ECDLP on this curve can be reduced to DLP in GF(p^$foundK)');

    // Severity assessment
    if (foundK <= 6) {
      print('   🔴 CRITICAL — Field extension too small, practical attack possible');
    } else if (foundK <= 20) {
      print('   🟠 WARNING — Field extension moderate, may be attackable with sufficient resources');
    } else {
      print('   🟡 CAUTION — Field extension relatively small but may still be secure');
    }
  } else {
    print('   ✅ SECURE — No small embedding degree found for k ≤ $maxK');
    print('   ✅ Curve is resistant to MOV attack');

    // Additional assurance
    if (maxK >= 32) {
      print('   📐 Embedding degree k > $maxK meets security requirements for 256-bit curves');
    }
  }

  // Background explanation
  print('\n📘 About MOV Attack:');
  print('   The MOV attack uses Weil or Tate pairings to map');
  print('   ECDLP instances from the curve to the multiplicative group');
  print('   of a finite field GF(p^k). If k is small, the DLP in');
  print('   GF(p^k) may be easier than ECDLP on the curve.');
  print('');
  print('   For 256-bit curves, k should be at least 32 to maintain');
  print('   equivalent security (~128 bits).');

  print('\n╚══════════════════════════════════════╝');
}