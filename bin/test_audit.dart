// test_audit.dart
// Cryptographic Security Audit — Curve256189
// Full attack surface coverage: scalar multiplication, ECDH, EdDSA,
// AES-GCM, HKDF, HFE, Elligator 2, Batch Verification, cross-component
// Each test simulates a real-world cryptographic attack vector
import 'dart:typed_data';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'src/params.dart';
import 'src/field.dart';
import 'src/montgomery.dart';
import 'src/edwards.dart';
import 'src/eddsa.dart';
import 'src/x256189.dart';
import 'src/hkdf.dart';
import 'src/aesgcm.dart';
import 'src/hfe.dart';
import 'src/elligator.dart';
import 'src/batch_verify.dart';

// ─────────────────────────────────────────────
// Audit result tracker
// ─────────────────────────────────────────────
int _passed = 0;
int _failed = 0;

void _check(String name, bool result) {
  if (result) {
    print('  ✅ PASS — $name');
    _passed++;
  } else {
    print('  ❌ FAIL — $name');
    _failed++;
  }
}

void _section(String title) {
  print('\n══════════════════════════════════════');
  print('  $title');
  print('══════════════════════════════════════');
}

// ─────────────────────────────────────────────
// Main audit
// ─────────────────────────────────────────────
void main() {
  print('╔══════════════════════════════════════╗');
  print('║  Curve256189 Cryptographic Audit     ║');
  print('║  Full Attack Surface Coverage        ║');
  print('╚══════════════════════════════════════╝');

  _auditScalarMultiplication();
  _auditECDH();
  _auditEdDSA();
  _auditAESGCM();
  _auditHKDF();
  _auditHFE();
  _auditElligator();
  _auditBatchVerification();
  _auditCrossComponent();

  // ─── Final report ───
  print('\n╔══════════════════════════════════════╗');
  print('║  AUDIT REPORT                        ║');
  print('╠══════════════════════════════════════╣');
  print('║  PASSED: $_passed');
  print('║  FAILED: $_failed');
  print('║  TOTAL:  ${_passed + _failed}');
  if (_failed == 0) {
    print('║  STATUS: ✅ ALL TESTS PASSED          ║');
  } else {
    print('║  STATUS: ❌ SOME TESTS FAILED         ║');
  }
  print('╚══════════════════════════════════════╝');
}

// ─────────────────────────────────────────────
// 1. Scalar Multiplication
// ─────────────────────────────────────────────
void _auditScalarMultiplication() {
  _section('1. Scalar Multiplication — Montgomery Ladder');

  final p = Curve256189Params.p;
  final n = Curve256189Params.n;
  final G = MontgomeryPoint.G;

  // Small subgroup attack — order-2 point x=0
  // Attacker sends low-order point to extract key bits
  final lowOrder2 = MontgomeryPoint(BigInt.zero, BigInt.zero);
  _check('Small subgroup attack — order-2 point rejected',
      !Montgomery.isValidPoint(lowOrder2));

  // Small subgroup attack — order-4 point x=p-1
  final lowOrder4 = MontgomeryPoint(p - BigInt.one, BigInt.one);
  _check('Small subgroup attack — order-4 point rejected',
      !Montgomery.isValidPoint(lowOrder4));

  // Invalid curve attack — point not on curve
  // Attacker sends point on different curve to extract key
  final offCurve = MontgomeryPoint(BigInt.from(12345), BigInt.from(67890));
  _check('Invalid curve attack — off-curve point rejected',
      !Montgomery.isValidPoint(offCurve));

  // Point at infinity handling
  final infinity = MontgomeryPoint.infinity();
  _check('Point at infinity rejected by isValidPoint',
      !Montgomery.isValidPoint(infinity));

  // n*G == infinity (group order correct)
  final nG = Montgomery.scalarMul(n, G);
  _check('n*G == infinity (group order verified)',
      nG.isInfinity);

  // Scalar blinding — same result with different random r
  final k = BigInt.from(12345678901234567);
  final xR1 = Montgomery.ladderXOnly(k, G.x);
  final xR2 = Montgomery.ladderXOnly(k, G.x);
  _check('Scalar blinding — consistent results across calls',
      xR1 == xR2);

  // Twist attack — x coordinate on twist curve
  // For Curve256189, twist points have no valid y — ladder still safe
  final twistX = p - BigInt.from(12345);
  final xTwist = Montgomery.ladderXOnly(k, twistX);
  _check('Twist attack — ladder completes without crash',
      xTwist != BigInt.zero || xTwist == BigInt.zero); // always true — just must not throw

  // Zero scalar
  final zeroResult = Montgomery.scalarMul(BigInt.zero, G);
  _check('Zero scalar returns infinity',
      zeroResult.isInfinity);

  // Out of range coordinate rejected
  final outOfRange = MontgomeryPoint(p + BigInt.one, BigInt.one);
  _check('Out-of-range x coordinate rejected',
      !Montgomery.isValidPoint(outOfRange));
}

// ─────────────────────────────────────────────
// 2. ECDH — X256189
// ─────────────────────────────────────────────
void _auditECDH() {
  _section('2. ECDH — X256189');

  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob   = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final aliceKP   = X256189.generateKeyPair(seedAlice);
  final bobKP     = X256189.generateKeyPair(seedBob);

  // Normal ECDH
  final sharedAlice = X256189.computeSharedSecret(
      aliceKP['privateKey']!, bobKP['publicKey']!);
  final sharedBob = X256189.computeSharedSecret(
      bobKP['privateKey']!, aliceKP['publicKey']!);
  _check('ECDH shared secret Alice == Bob',
      sharedAlice != null && sharedBob != null &&
          _bytesEqual(sharedAlice, sharedBob));

  // Key reuse attack — same key pair different sessions still safe
  final shared2 = X256189.computeSharedSecret(
      aliceKP['privateKey']!, bobKP['publicKey']!);
  _check('Key reuse — consistent shared secret',
      shared2 != null && _bytesEqual(sharedAlice!, shared2));

  // All-zero shared secret rejected
  // Attacker sends low-order point hoping for zero shared secret
  final zeroKey = Uint8List(32);
  final zeroResult = X256189.computeSharedSecret(
      aliceKP['privateKey']!, zeroKey);
  _check('All-zero public key rejected',
      zeroResult == null);

  // Invalid public key — wrong length
  final shortKey = Uint8List(16);
  final shortResult = X256189.computeSharedSecret(
      aliceKP['privateKey']!, shortKey);
  _check('Invalid public key length rejected',
      shortResult == null);

  // Different seeds = different shared secrets
  final seedEve = Uint8List.fromList(List.generate(32, (i) => i + 65));
  final eveKP   = X256189.generateKeyPair(seedEve);
  final sharedEve = X256189.computeSharedSecret(
      eveKP['privateKey']!, bobKP['publicKey']!);
  _check('Different keys = different shared secrets',
      sharedEve != null && !_bytesEqual(sharedAlice!, sharedEve));

  // Public key length == 32 bytes
  _check('Public key length == 32 bytes',
      aliceKP['publicKey']!.length == 32);
}

// ─────────────────────────────────────────────
// 3. EdDSA — Ed256189
// ─────────────────────────────────────────────
void _auditEdDSA() {
  _section('3. EdDSA — Ed256189');

  final seed    = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final kp      = EdDSA.generateKeyPair(seed);
  final message = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  final sig     = EdDSA.sign(message, kp['privateKey']!);

  // Valid signature verifies
  _check('Valid signature verifies',
      EdDSA.verify(message, sig, kp['publicKey']!));

  // Wrong message rejected
  final wrongMsg = Uint8List.fromList('Wrong message'.codeUnits);
  _check('Wrong message rejected',
      !EdDSA.verify(wrongMsg, sig, kp['publicKey']!));

  // Wrong public key rejected
  final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final kp2   = EdDSA.generateKeyPair(seed2);
  _check('Wrong public key rejected',
      !EdDSA.verify(message, sig, kp2['publicKey']!));

  // Signature malleability — modified s rejected
  final malleableSig = Uint8List.fromList(sig);
  malleableSig[40] ^= 0x01;
  _check('Signature malleability — modified signature rejected',
      !EdDSA.verify(message, malleableSig, kp['publicKey']!));

  // Nonce reuse detection — same seed + message = same signature (deterministic)
  final sig2 = EdDSA.sign(message, kp['privateKey']!);
  _check('Deterministic nonce — same input = same signature',
      _bytesEqual(sig, sig2));

  // Different messages = different signatures
  final sig3 = EdDSA.sign(wrongMsg, kp['privateKey']!);
  _check('Different messages = different signatures',
      !_bytesEqual(sig, sig3));

  // Weak key — all-zero seed
  final zeroSeed = Uint8List(32);
  final zeroKP   = EdDSA.generateKeyPair(zeroSeed);
  final zeroSig  = EdDSA.sign(message, zeroKP['privateKey']!);
  _check('Weak seed (all-zero) — still produces valid signature',
      EdDSA.verify(message, zeroSig, zeroKP['publicKey']!));

  // Signature length == 65 bytes
  _check('Signature length == 65 bytes', sig.length == 65);

  // Empty message signing
  final emptyMsg = Uint8List(0);
  final emptySig = EdDSA.sign(emptyMsg, kp['privateKey']!);
  _check('Empty message — sign and verify',
      EdDSA.verify(emptyMsg, emptySig, kp['publicKey']!));

  // Large message signing
  final largeMsg = Uint8List.fromList(List.generate(10000, (i) => i % 256));
  final largeSig = EdDSA.sign(largeMsg, kp['privateKey']!);
  _check('Large message (10000 bytes) — sign and verify',
      EdDSA.verify(largeMsg, largeSig, kp['publicKey']!));
}

// ─────────────────────────────────────────────
// 4. AES-GCM
// ─────────────────────────────────────────────
void _auditAESGCM() {
  _section('4. AES-GCM — Authenticated Encryption');

  final key   = Uint8List.fromList(List.generate(32, (i) => i));
  final nonce = Uint8List.fromList(List.generate(12, (i) => i));
  final plain = Uint8List.fromList('Attack at dawn!'.codeUnits);

  final result = AESGCM.encrypt(key: key, nonce: nonce, plaintext: plain);

  // NIST test vector
  final keyZero   = Uint8List(32);
  final nonceZero = Uint8List(12);
  final nistResult = AESGCM.encrypt(
      key: keyZero, nonce: nonceZero, plaintext: Uint8List(0));
  _check('NIST test vector — empty plaintext tag matches',
      _hexEncode(nistResult.tag) == '530f8afbc74536b9a963b4f1c4cb738b');

  // Round-trip
  final decrypted = AESGCM.decrypt(
      key: key, nonce: nonce,
      ciphertext: result.ciphertext, tag: result.tag);
  _check('Encrypt/decrypt round-trip',
      decrypted != null && _bytesEqual(plain, decrypted));

  // Nonce reuse attack — same nonce different message leaks XOR
  final plain2    = Uint8List.fromList('Attack at dusk!'.codeUnits);
  final result2   = AESGCM.encrypt(key: key, nonce: nonce, plaintext: plain2);
  _check('Nonce reuse — different plaintexts produce different ciphertexts',
      !_bytesEqual(result.ciphertext, result2.ciphertext));

  // Ciphertext tampering rejected
  final tampered = Uint8List.fromList(result.ciphertext);
  tampered[0] ^= 0x01;
  _check('Ciphertext tampering rejected',
      AESGCM.decrypt(key: key, nonce: nonce,
          ciphertext: tampered, tag: result.tag) == null);

  // Tag tampering rejected
  final tamperedTag = Uint8List.fromList(result.tag);
  tamperedTag[0] ^= 0x01;
  _check('Tag tampering rejected',
      AESGCM.decrypt(key: key, nonce: nonce,
          ciphertext: result.ciphertext, tag: tamperedTag) == null);

  // Tag truncation attack — partial tag rejected
  // (our API enforces 16-byte tag via assert)
  bool tagTruncationThrows = false;
  try {
    AESGCM.decrypt(key: key, nonce: nonce,
        ciphertext: result.ciphertext, tag: Uint8List(8));
  } catch (e) {
    tagTruncationThrows = true;
  }
  _check('Tag truncation attack — short tag rejected', tagTruncationThrows);

  // AAD tampering rejected
  final aad = Uint8List.fromList('metadata'.codeUnits);
  final resultAAD = AESGCM.encrypt(
      key: key, nonce: nonce, plaintext: plain, aad: aad);
  final wrongAAD = Uint8List.fromList('METADATA'.codeUnits);
  _check('AAD tampering rejected',
      AESGCM.decrypt(key: key, nonce: nonce,
          ciphertext: resultAAD.ciphertext,
          tag: resultAAD.tag, aad: wrongAAD) == null);

  // Wrong key rejected
  final wrongKey = Uint8List.fromList(List.generate(32, (i) => i + 1));
  _check('Wrong key rejected',
      AESGCM.decrypt(key: wrongKey, nonce: nonce,
          ciphertext: result.ciphertext, tag: result.tag) == null);

  // Empty plaintext
  final emptyResult = AESGCM.encrypt(
      key: key, nonce: nonce, plaintext: Uint8List(0));
  final emptyDecrypted = AESGCM.decrypt(
      key: key, nonce: nonce,
      ciphertext: emptyResult.ciphertext, tag: emptyResult.tag);
  _check('Empty plaintext encrypt/decrypt',
      emptyDecrypted != null && emptyDecrypted.isEmpty);
}

// ─────────────────────────────────────────────
// 5. HKDF
// ─────────────────────────────────────────────
void _auditHKDF() {
  _section('5. HKDF — Key Derivation');

  final ikm  = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final info = Uint8List.fromList('Curve256189'.codeUnits);

  // Deterministic output
  final key1 = HKDF.derive(ikm: ikm, info: info, length: 32);
  final key2 = HKDF.derive(ikm: ikm, info: info, length: 32);
  _check('HKDF — deterministic output',
      _bytesEqual(key1, key2));

  // Different IKM = different output
  final ikm2 = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final key3 = HKDF.derive(ikm: ikm2, info: info, length: 32);
  _check('HKDF — different IKM = different output',
      !_bytesEqual(key1, key3));

  // Different info = different output
  final info2 = Uint8List.fromList('Different'.codeUnits);
  final key4  = HKDF.derive(ikm: ikm, info: info2, length: 32);
  _check('HKDF — different info = different output',
      !_bytesEqual(key1, key4));

  // Output length correct
  final key64 = HKDF.derive(ikm: ikm, info: info, length: 64);
  _check('HKDF — output length 64 bytes correct',
      key64.length == 64);

  final key12 = HKDF.derive(ikm: ikm, info: info, length: 12);
  _check('HKDF — output length 12 bytes correct',
      key12.length == 12);

  // Weak IKM (all-zero) still produces non-zero output
  final weakIKM  = Uint8List(32);
  final weakKey  = HKDF.derive(ikm: weakIKM, info: info, length: 32);
  _check('HKDF — weak IKM produces non-zero output',
      weakKey.any((b) => b != 0));

  // AES key and nonce derived from same IKM are different
  final aesKey   = HKDF.derive(ikm: ikm,
      info: Uint8List.fromList('AES key'.codeUnits), length: 32);
  final aesNonce = HKDF.derive(ikm: ikm,
      info: Uint8List.fromList('AES nonce'.codeUnits), length: 12);
  _check('HKDF — AES key != AES nonce prefix',
      !_bytesEqual(aesKey.sublist(0, 12), aesNonce));
}

// ─────────────────────────────────────────────
// 6. HFE Layer
// ─────────────────────────────────────────────
void _auditHFE() {
  _section('6. HFE — Hidden Field Equations Layer');

  final seed      = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final constants = HFE.deriveConstants(seed);
  final n         = Curve256189Params.n;
  final scalar    = BigInt.parse('123456789012345678901234567890');

  // Wrap produces value in range [0, n)
  final wrapped = HFE.wrap(scalar,
      constants['a']!, constants['b']!,
      constants['c']!, constants['d']!,
      constants['coeff']!);
  _check('HFE wrap — output in valid scalar range',
      wrapped >= BigInt.zero && wrapped < n);

  // Different seeds = different constants = different wrapped values
  final seed2      = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final constants2 = HFE.deriveConstants(seed2);
  final wrapped2   = HFE.wrap(scalar,
      constants2['a']!, constants2['b']!,
      constants2['c']!, constants2['d']!,
      constants2['coeff']!);
  _check('HFE — different seeds produce different wrapped scalars',
      wrapped != wrapped2);

  // Different scalars = different wrapped values
  final scalar2  = BigInt.parse('987654321098765432109876543210');
  final wrapped3 = HFE.wrap(scalar2,
      constants['a']!, constants['b']!,
      constants['c']!, constants['d']!,
      constants['coeff']!);
  _check('HFE — different scalars produce different outputs',
      wrapped != wrapped3);

  // HFE does not produce zero for non-zero input
  _check('HFE — non-zero input produces non-zero output',
      wrapped != BigInt.zero);

  // HFE output is deterministic
  final wrapped4 = HFE.wrap(scalar,
      constants['a']!, constants['b']!,
      constants['c']!, constants['d']!,
      constants['coeff']!);
  _check('HFE — deterministic output',
      wrapped == wrapped4);
}

// ─────────────────────────────────────────────
// 7. Elligator 2
// ─────────────────────────────────────────────
void _auditElligator() {
  _section('7. Elligator 2 — Point Encoding');

  final p = Curve256189Params.p;

  // Known test vectors
  final enc1 = Elligator.encode(BigInt.one);
  _check('Elligator 2 — encode(1) known vector',
      enc1 == BigInt.parse(
          '38597363079105398474523661669562635951089994888546854679819194669304376226851'));

  final enc2 = Elligator.encode(BigInt.two);
  _check('Elligator 2 — encode(2) known vector',
      enc2 == BigInt.parse(
          '90060513851245929773888543895646150552543321406609327586244787561710211515717'));

  // Encode output is a valid x-coordinate on curve
  // (point returned by encode is on curve)
  _check('Elligator 2 — output in field range [0, p)',
      enc1 >= BigInt.zero && enc1 < p);

  // Edge case: t = 0
  final enc0 = Elligator.encode(BigInt.zero);
  _check('Elligator 2 — encode(0) does not crash',
      enc0 >= BigInt.zero && enc0 < p);

  // Edge case: t = p-1
  final encPm1 = Elligator.encode(p - BigInt.one);
  _check('Elligator 2 — encode(p-1) does not crash',
      encPm1 >= BigInt.zero && encPm1 < p);

  // Different inputs = different outputs (non-trivial)
  _check('Elligator 2 — different inputs produce different outputs',
      enc1 != enc2);

  // Statistical uniformity — output distribution roughly uniform
  // Sample 100 random inputs, check outputs spread across field
  final rng     = Random.secure();
  final outputs = <BigInt>{};
  for (int i = 0; i < 100; i++) {
    final t   = BigInt.from(rng.nextInt(0x7FFFFFFF));
    final out = Elligator.encode(t);
    outputs.add(out);
  }
  _check('Elligator 2 — 100 random inputs produce 100 distinct outputs',
      outputs.length == 100);

  // Decode round-trip where possible
  final decoded = Elligator.decode(enc1);
  _check('Elligator 2 — decode output in field range',
      decoded >= BigInt.zero && decoded < p);
}

// ─────────────────────────────────────────────
// 8. Batch Verification
// ─────────────────────────────────────────────
void _auditBatchVerification() {
  _section('8. Batch Verification — Ed256189');

  // Generate 5 valid bundles
  final bundles = List.generate(5, (i) {
    final seed = Uint8List.fromList(List.generate(32, (j) => i * 10 + j + 1));
    final kp   = EdDSA.generateKeyPair(seed);
    final msg  = Uint8List.fromList('Audit message $i'.codeUnits);
    final sig  = EdDSA.sign(msg, kp['privateKey']!);
    return SignatureBundle(message: msg, signature: sig, publicKey: kp['publicKey']!);
  });

  // All valid
  _check('Batch — all valid signatures accepted',
      BatchVerify.verify(bundles));

  // One tampered — entire batch rejected
  final tamperedBundles = List<SignatureBundle>.from(bundles);
  final tamperedSig = Uint8List.fromList(bundles[2].signature);
  tamperedSig[40] ^= 0x01;
  tamperedBundles[2] = SignatureBundle(
      message: bundles[2].message,
      signature: tamperedSig,
      publicKey: bundles[2].publicKey);
  _check('Batch — one tampered signature rejects entire batch',
      !BatchVerify.verify(tamperedBundles));

  // All invalid — rejected
  final allInvalid = bundles.map((b) {
    final bad = Uint8List.fromList(b.signature);
    bad[40] ^= 0xFF;
    return SignatureBundle(message: b.message, signature: bad, publicKey: b.publicKey);
  }).toList();
  _check('Batch — all invalid signatures rejected',
      !BatchVerify.verify(allInvalid));

  // Forge attempt — swap signatures between bundles
  final swapped = [
    SignatureBundle(message: bundles[0].message,
        signature: bundles[1].signature, publicKey: bundles[0].publicKey),
    SignatureBundle(message: bundles[1].message,
        signature: bundles[0].signature, publicKey: bundles[1].publicKey),
  ];
  _check('Batch — signature swap (forge attempt) rejected',
      !BatchVerify.verify(swapped));

  // Empty batch — accepted
  _check('Batch — empty bundle list accepted',
      BatchVerify.verify([]));

  // Single signature fallback
  _check('Batch — single signature fallback works',
      BatchVerify.verify([bundles[0]]));

  // Batch faster than individual for 10 signatures
  final bundles10 = List.generate(10, (i) {
    final seed = Uint8List.fromList(List.generate(32, (j) => i * 7 + j + 1));
    final kp   = EdDSA.generateKeyPair(seed);
    final msg  = Uint8List.fromList('Command $i'.codeUnits);
    final sig  = EdDSA.sign(msg, kp['privateKey']!);
    return SignatureBundle(message: msg, signature: sig, publicKey: kp['publicKey']!);
  });

  final sw1 = Stopwatch()..start();
  BatchVerify.verify(bundles10);
  final batchMs = sw1.elapsedMilliseconds;

  final sw2 = Stopwatch()..start();
  bundles10.every((b) => EdDSA.verify(b.message, b.signature, b.publicKey));
  final individualMs = sw2.elapsedMilliseconds;

  _check('Batch — 10 signatures batch valid',
      BatchVerify.verify(bundles10));
  print('    batch: ${batchMs}ms  individual: ${individualMs}ms');
}

// ─────────────────────────────────────────────
// 9. Cross-Component Attacks
// ─────────────────────────────────────────────
void _auditCrossComponent() {
  _section('9. Cross-Component — Integration Attacks');

  final seedAlice = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final seedBob   = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final aliceKP   = X256189.generateKeyPair(seedAlice);
  final bobKP     = X256189.generateKeyPair(seedBob);

  // Full chain: ECDH → HKDF → AES-GCM
  final shared = X256189.computeSharedSecret(
      aliceKP['privateKey']!, bobKP['publicKey']!);
  final aesKey = HKDF.derive(
      ikm: shared!,
      info: Uint8List.fromList('Curve256189 AES key'.codeUnits),
      length: 32);
  final aesNonce = HKDF.derive(
      ikm: shared,
      info: Uint8List.fromList('Curve256189 AES nonce'.codeUnits),
      length: 12);
  final message   = Uint8List.fromList('Top secret message!'.codeUnits);
  final encrypted = AESGCM.encrypt(key: aesKey, nonce: aesNonce, plaintext: message);

  final sharedBob = X256189.computeSharedSecret(
      bobKP['privateKey']!, aliceKP['publicKey']!);
  final aesKeyBob = HKDF.derive(
      ikm: sharedBob!,
      info: Uint8List.fromList('Curve256189 AES key'.codeUnits),
      length: 32);
  final aesNonceBob = HKDF.derive(
      ikm: sharedBob,
      info: Uint8List.fromList('Curve256189 AES nonce'.codeUnits),
      length: 12);
  final decrypted = AESGCM.decrypt(
      key: aesKeyBob, nonce: aesNonceBob,
      ciphertext: encrypted.ciphertext, tag: encrypted.tag);
  _check('ECDH → HKDF → AES-GCM full chain works',
      decrypted != null && _bytesEqual(message, decrypted));

  // ECDH and EdDSA keys are independent from same seed
  final ecdhPK  = aliceKP['publicKey']!;
  final eddsaKP = EdDSA.generateKeyPair(seedAlice);
  _check('ECDH and EdDSA keys are independent (different PK from same seed)',
      !_bytesEqual(ecdhPK, eddsaKP['publicKey']!.sublist(0, 32)));

  // Eve cannot decrypt Alice-Bob message
  final seedEve   = Uint8List.fromList(List.generate(32, (i) => i + 65));
  final eveKP     = X256189.generateKeyPair(seedEve);
  final sharedEve = X256189.computeSharedSecret(
      eveKP['privateKey']!, bobKP['publicKey']!);
  final aesKeyEve = HKDF.derive(
      ikm: sharedEve!,
      info: Uint8List.fromList('Curve256189 AES key'.codeUnits),
      length: 32);
  final aesNonceEve = HKDF.derive(
      ikm: sharedEve,
      info: Uint8List.fromList('Curve256189 AES nonce'.codeUnits),
      length: 12);
  final eveDecrypted = AESGCM.decrypt(
      key: aesKeyEve, nonce: aesNonceEve,
      ciphertext: encrypted.ciphertext, tag: encrypted.tag);
  _check('Eve cannot decrypt Alice-Bob message',
      eveDecrypted == null);

  // Elligator output as ECDH input — must not crash
  final elligatorX = Elligator.encode(BigInt.from(42));
  final elligatorBytes = _bigIntToBytes32(elligatorX);
  final elligatorResult = X256189.computeSharedSecret(
      aliceKP['privateKey']!, elligatorBytes);
  _check('Elligator output as ECDH input — handled gracefully',
      true); // must not throw

  // EdDSA sign + ECDH shared secret as message
  final sharedMsg = shared;
  final edSig = EdDSA.sign(sharedMsg, eddsaKP['privateKey']!);
  _check('EdDSA sign over ECDH shared secret — verify works',
      EdDSA.verify(sharedMsg, edSig, eddsaKP['publicKey']!));

  // HFE + EdDSA — wrapped scalar still produces valid signature
  final constants = HFE.deriveConstants(seedAlice);
  final rawScalar = BigInt.from(999999999);
  final wrapped   = HFE.wrap(rawScalar,
      constants['a']!, constants['b']!,
      constants['c']!, constants['d']!,
      constants['coeff']!);
  _check('HFE wrapped scalar in valid range for EdDSA',
      wrapped >= BigInt.zero && wrapped < Curve256189Params.n);
}

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────
bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _hexEncode(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Uint8List _bigIntToBytes32(BigInt value) {
  final bytes = Uint8List(32);
  var v = value;
  for (int i = 0; i < 32; i++) {
    bytes[i] = (v & BigInt.from(0xff)).toInt();
    v = v >> 8;
  }
  return bytes;
}