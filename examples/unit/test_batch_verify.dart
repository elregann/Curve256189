// test_batch_verify.dart

// Batch verification of Ed256189 signatures
// Based on the batch verification technique by Daniel J. Bernstein (2012)
// Formalized for Edwards curves by Henry de Valence et al. (2017)
// Adapted for Curve256189 by Ismael Urzaiz Aranda (2026)
import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

void main() {
  print('=== Test: Batch Verification Ed256189 ===');

  // Test case 1: Single signature verification (falls back to individual verify)
  print('');
  print('Test 1 - Single signature fallback:');
  final seed1 = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final kp1 = EdDSA.generateKeyPair(seed1);
  final msg1 = Uint8List.fromList('Hello Curve256189!'.codeUnits);
  final sig1 = EdDSA.sign(msg1, kp1['privateKey']!);
  final result1 = BatchVerify.verify([
    SignatureBundle(message: msg1, signature: sig1, publicKey: kp1['publicKey']!),
  ]);
  print('  single valid? $result1');

  // Test case 2: Batch verification of 2 valid signatures
  print('');
  print('Test 2 - Batch verify 2 signatures:');
  final seed2 = Uint8List.fromList(List.generate(32, (i) => i + 33));
  final kp2 = EdDSA.generateKeyPair(seed2);
  final msg2 = Uint8List.fromList('Batch verification rocks!'.codeUnits);
  final sig2 = EdDSA.sign(msg2, kp2['privateKey']!);
  final result2 = BatchVerify.verify([
    SignatureBundle(message: msg1, signature: sig1, publicKey: kp1['publicKey']!),
    SignatureBundle(message: msg2, signature: sig2, publicKey: kp2['publicKey']!),
  ]);
  print('  batch 2 valid? $result2');

  // Test case 3: Batch verification of 5 valid signatures
  print('');
  print('Test 3 - Batch verify 5 signatures:');
  final bundles5 = List.generate(5, (i) {
    final seed = Uint8List.fromList(List.generate(32, (j) => i * 32 + j + 1));
    final kp = EdDSA.generateKeyPair(seed);
    final msg = Uint8List.fromList('Message $i'.codeUnits);
    final sig = EdDSA.sign(msg, kp['privateKey']!);
    return SignatureBundle(message: msg, signature: sig, publicKey: kp['publicKey']!);
  });
  final result3 = BatchVerify.verify(bundles5);
  print('  batch 5 valid? $result3');

  // Test case 4: Tampered signature is rejected in batch verification
  print('');
  print('Test 4 - Tampered signature rejected in batch:');
  final tamperedSig = Uint8List.fromList(sig1);
  tamperedSig[40] ^= 0x01;
  final result4 = BatchVerify.verify([
    SignatureBundle(message: msg1, signature: tamperedSig, publicKey: kp1['publicKey']!),
    SignatureBundle(message: msg2, signature: sig2, publicKey: kp2['publicKey']!),
  ]);
  print('  tampered rejected? ${result4 == false}');

  // Test case 5: Wrong message is rejected in batch verification
  print('');
  print('Test 5 - Wrong message rejected in batch:');
  final wrongMsg = Uint8List.fromList('Wrong message!'.codeUnits);
  final result5 = BatchVerify.verify([
    SignatureBundle(message: wrongMsg, signature: sig1, publicKey: kp1['publicKey']!),
    SignatureBundle(message: msg2, signature: sig2, publicKey: kp2['publicKey']!),
  ]);
  print('  wrong message rejected? ${result5 == false}');

  // Test case 6: Batch verification of 10 signatures — throughput demonstration
  print('');
  print('Test 6 - Batch verify 10 signatures (throughput demo):');
  final bundles10 = List.generate(10, (i) {
    final seed = Uint8List.fromList(List.generate(32, (j) => i * 7 + j + 1));
    final kp = EdDSA.generateKeyPair(seed);
    final msg = Uint8List.fromList('Command $i — fire!'.codeUnits);
    final sig = EdDSA.sign(msg, kp['privateKey']!);
    return SignatureBundle(message: msg, signature: sig, publicKey: kp['publicKey']!);
  });

  final stopwatch = Stopwatch()..start();
  final result6batch = BatchVerify.verify(bundles10);
  final batchTime = stopwatch.elapsedMilliseconds;

  stopwatch.reset();
  stopwatch.start();
  final result6individual = bundles10.every((b) =>
      EdDSA.verify(b.message, b.signature, b.publicKey)
  );
  final individualTime = stopwatch.elapsedMilliseconds;

  print('  individual valid? $result6individual');
  print('  batch valid? $result6batch');
  print('  individual time: ${individualTime} ms');
  print('  batch time:      ${batchTime} ms');
}