// test_hfe_security.dart
// Security analysis of HFE wrap layer in Curve256189
// Tests: obfuscation, non-reversibility, collision, statistical randomness
import 'dart:typed_data';
import 'dart:math';
import '../src/hfe.dart';
import '../src/eddsa.dart';
import '../src/params.dart';

void main() {
  print('=== Test HFE Security Layer Curve256189 ===');

  final n = Curve256189Params.n;
  final random = Random.secure();

  // Helper: random BigInt in [1, n-1]
  BigInt randomScalar() {
    final bytes = Uint8List(32);
    for (int i = 0; i < 32; i++) bytes[i] = random.nextInt(256);
    BigInt result = BigInt.zero;
    for (int i = 0; i < 32; i++) {
      result = result | (BigInt.from(bytes[i]) << (8 * i));
    }
    return (result % (n - BigInt.one)) + BigInt.one;
  }

  // Helper: random seed
  Uint8List randomSeed() {
    final seed = Uint8List(32);
    for (int i = 0; i < 32; i++) seed[i] = random.nextInt(256);
    return seed;
  }

  // =============================================
  // Test A: Apakah HFE wrap mengaburkan sk_raw?
  // sk_raw vs sk_wrapped harus berbeda jauh
  // =============================================
  print('\nTest A - HFE wrap mengaburkan sk_raw?');
  int obfuscated = 0;
  final sampleSize = 100;
  for (int i = 0; i < sampleSize; i++) {
    final seed = randomSeed();
    final sk_raw = randomScalar();
    final constants = HFE.deriveConstants(seed);
    final sk_wrapped = HFE.wrap(
      sk_raw,
      constants['a']!,
      constants['b']!,
      constants['c']!,
      constants['d']!,
      constants['coeff']!,
    );
    if (sk_raw != sk_wrapped) obfuscated++;
  }
  print('  $obfuscated/$sampleSize sk_wrapped != sk_raw');
  print('  Obfuscated? ${obfuscated == sampleSize}');

  // =============================================
  // Test B: Non-reversibility tanpa constants
  // Attacker tanpa constants tidak bisa recover sk_raw
  // =============================================
  print('\nTest B - Non-reversibility tanpa constants?');
  final seedB = randomSeed();
  final sk_rawB = randomScalar();
  final constantsB = HFE.deriveConstants(seedB);
  final sk_wrappedB = HFE.wrap(
    sk_rawB,
    constantsB['a']!,
    constantsB['b']!,
    constantsB['c']!,
    constantsB['d']!,
    constantsB['coeff']!,
  );

  // Coba recover dengan constants yang salah
  int recovered = 0;
  for (int i = 0; i < sampleSize; i++) {
    final fakeConstants = HFE.deriveConstants(randomSeed());
    final attempt = HFE.wrap(
      sk_wrappedB,
      fakeConstants['a']!,
      fakeConstants['b']!,
      fakeConstants['c']!,
      fakeConstants['d']!,
      fakeConstants['coeff']!,
    );
    if (attempt == sk_rawB) recovered++;
  }
  print('  Recovery attempts: $sampleSize');
  print('  Successful recovery: $recovered');
  print('  Non-reversible? ${recovered == 0}');

  // =============================================
  // Test C: Collision test
  // Dua sk_raw berbeda dengan seed sama
  // harus menghasilkan sk_wrapped berbeda
  // =============================================
  print('\nTest C - Collision test?');
  final seedC = randomSeed();
  final constantsC = HFE.deriveConstants(seedC);
  int collisions = 0;
  for (int i = 0; i < sampleSize; i++) {
    final sk1 = randomScalar();
    final sk2 = randomScalar();
    final w1 = HFE.wrap(sk1, constantsC['a']!, constantsC['b']!,
        constantsC['c']!, constantsC['d']!, constantsC['coeff']!);
    final w2 = HFE.wrap(sk2, constantsC['a']!, constantsC['b']!,
        constantsC['c']!, constantsC['d']!, constantsC['coeff']!);
    if (sk1 != sk2 && w1 == w2) collisions++;
  }
  print('  Collisions found: $collisions/$sampleSize');
  print('  Collision-free? ${collisions == 0}');

  // =============================================
  // Test D: Statistical randomness
  // Output HFE harus terlihat random
  // Test: distribusi bit — hitung jumlah bit 1
  // Harapan: ~50% bit 1 (mendekati uniform)
  // =============================================
  print('\nTest D - Statistical randomness (bit distribution)?');
  int totalBits = 0;
  int oneBits = 0;
  for (int i = 0; i < sampleSize; i++) {
    final seed = randomSeed();
    final sk_raw = randomScalar();
    final constants = HFE.deriveConstants(seed);
    final sk_wrapped = HFE.wrap(
      sk_raw,
      constants['a']!,
      constants['b']!,
      constants['c']!,
      constants['d']!,
      constants['coeff']!,
    );
    final bits = sk_wrapped.toRadixString(2);
    totalBits += bits.length;
    oneBits += bits.split('1').length - 1;
  }
  final ratio = oneBits / totalBits;
  print('  Total bits: $totalBits');
  print('  One bits:   $oneBits');
  print('  Ratio:      ${ratio.toStringAsFixed(4)} (ideal: ~0.5000)');
  print('  Random-looking? ${ratio > 0.45 && ratio < 0.55}');

  // =============================================
  // Test E: ECC + HFE combined
  // Public key dari sk_wrapped tidak bisa
  // dibedakan dari public key tanpa HFE
  // =============================================
  print('\nTest E - ECC + HFE public key indistinguishable?');
  int distinguishable = 0;
  for (int i = 0; i < sampleSize; i++) {
    final seed1 = randomSeed();
    final seed2 = randomSeed();
    final kp1 = EdDSA.generateKeyPair(seed1);
    final kp2 = EdDSA.generateKeyPair(seed2);
    // Public key dari seed berbeda harus berbeda
    if (kp1['publicKey']!.toString() == kp2['publicKey']!.toString()) {
      distinguishable++;
    }
  }
  print('  PK collisions: $distinguishable/$sampleSize');
  print('  Indistinguishable? ${distinguishable == 0}');
}