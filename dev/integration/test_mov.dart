// test_mov.dart

// MOV Attack Vulnerability Test for Curve256189
//
// The MOV (Menezes-Okamoto-Vanstone) attack reduces the ECDLP to a DLP in GF(p^k)
// when the embedding degree k is small. For secure curves, k must be large
// (typically greater than (log p) / 8, which is approximately 32 for 256-bit curves).

import 'package:curve256189/curve256189.dart';

void main() {
  print('Curve256189 MOV Attack Test');
  print('');

  final p = Curve256189Params.p;  // Field characteristic
  final n = Curve256189Params.n;  // Curve order

  print('Parameters:');
  print('  p (field characteristic) = $p');
  print('  n (curve order)          = $n');

  // Check for the trivial case where p ≡ 1 mod n, which gives embedding degree k = 1
  if (p % n == BigInt.one) {
    print('');
    print('WARNING: p ≡ 1 mod n, therefore embedding degree k = 1');
    print('  The curve is completely INSECURE against the MOV attack.');
    return;
  }

  const maxK = 50;
  print('');
  print('Searching for embedding degree k <= $maxK...');
  print('  Condition: p^k ≡ 1 mod n');

  BigInt pk = p % n;
  int? foundK;

  for (int k = 1; k <= maxK; k++) {
    if (pk == BigInt.one) {
      foundK = k;
      break;
    }
    pk = (pk * p) % n;
  }

  // MOV analysis results
  print('');
  print('MOV Analysis Results:');

  if (foundK != null) {
    print('  VULNERABLE: embedding degree k = $foundK');
    print('  The ECDLP on this curve can be reduced to DLP in GF(p^$foundK)');

    // Severity assessment based on the embedding degree
    if (foundK <= 6) {
      print('  CRITICAL: Field extension is too small, practical attack is possible.');
    } else if (foundK <= 20) {
      print('  WARNING: Field extension is moderate; attack may be possible with sufficient resources.');
    } else {
      print('  CAUTION: Field extension is relatively small but may still be secure.');
    }
  } else {
    print('  SECURE: No small embedding degree found for k <= $maxK');
    print('  The curve is resistant to the MOV attack.');

    // Additional assurance for sufficiently large search bound
    if (maxK >= 32) {
      print('  Embedding degree k > $maxK meets security requirements for 256-bit curves.');
    }
  }

  // Background explanation of the MOV attack
  print('');
  print('About the MOV Attack:');
  print('  The MOV attack uses Weil or Tate pairings to map');
  print('  ECDLP instances from the curve to the multiplicative group');
  print('  of a finite field GF(p^k). If k is small, the DLP in');
  print('  GF(p^k) may be easier than the ECDLP on the curve.');
  print('');
  print('  For 256-bit curves, k should be at least 32 to maintain');
  print('  equivalent security (approximately 128 bits).');
  print('');
  print('=== MOV Attack Test Completed ===');
}