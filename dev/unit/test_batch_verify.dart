// test_batch_verify.dart

// Batch verification of XEdDSA signatures on Curve256189.
import 'dart:typed_data';
import 'package:curve256189/curve256189.dart';

int _passed = 0;
int _failed = 0;

void _check(String name, bool result) {
  print('  ${result ? "PASS" : "FAIL"}: $name');
  if (result) {
    _passed++;
  } else {
    _failed++;
  }
}

SignatureBundle _bundle(int seedOffset, String message) {
  final seed =
      Uint8List.fromList(List.generate(32, (i) => (seedOffset + i) & 0xff));
  final kp = XEdDSA.generateKeyPair(seed);
  final msg = Uint8List.fromList(message.codeUnits);
  final sig = XEdDSA.sign(msg, kp['privateKey']!);
  return SignatureBundle(
    message: msg,
    signature: sig,
    publicKey: kp['publicKey']!,
  );
}

void main() {
  print('=== Test: Batch Verification XEdDSA ===');
  print('');

  final b1 = _bundle(1, 'Hello Curve256189!');
  final b2 = _bundle(33, 'Batch verification rocks!');

  print('Test 1 - Single signature fallback:');
  _check('single valid signature accepted', BatchVerify.verify([b1]));
  _check('empty batch accepted', BatchVerify.verify([]));

  print('');
  print('Test 2 - Valid batches:');
  _check('2-signature batch accepted', BatchVerify.verify([b1, b2]));

  final batches = List.generate(
    5,
    (i) => _bundle(i * 32 + 1, 'Message $i'),
  );
  _check('5-signature batch accepted', BatchVerify.verify(batches));

  print('');
  print('Test 3 - Tampering is rejected:');
  final tampered = Uint8List.fromList(b1.signature);
  tampered[40] ^= 0x01;
  _check(
    'tampered signature rejected',
    !BatchVerify.verify([
      SignatureBundle(
          message: b1.message, signature: tampered, publicKey: b1.publicKey),
      b2,
    ]),
  );

  _check(
    'wrong message rejected',
    !BatchVerify.verify([
      SignatureBundle(
          message: Uint8List.fromList('Wrong message!'.codeUnits),
          signature: b1.signature,
          publicKey: b1.publicKey),
      b2,
    ]),
  );

  final n = Curve256189Params.n;
  final xR = Uint8List.fromList(b1.signature.sublist(0, 32));
  final s =
      XEdDSA.decodeLittleEndian(Uint8List.fromList(b1.signature.sublist(32)));

  final nMinusS =
      Uint8List.fromList([...xR, ...XEdDSA.encodeScalar((n - s) % n)]);
  _check(
    '(x(R), n - s) rejected in batch',
    !BatchVerify.verify([
      SignatureBundle(
          message: b1.message, signature: nMinusS, publicKey: b1.publicKey),
      b2,
    ]),
  );

  var sPlusN = s + n;
  final sPlusNBytes = Uint8List(32);
  for (int i = 0; i < 32; i++) {
    sPlusNBytes[i] = (sPlusN & BigInt.from(0xff)).toInt();
    sPlusN >>= 8;
  }
  final nonCanonicalS = Uint8List.fromList([...xR, ...sPlusNBytes]);
  _check(
    '(x(R), s + n) rejected in batch',
    !BatchVerify.verify([
      SignatureBundle(
          message: b1.message,
          signature: nonCanonicalS,
          publicKey: b1.publicKey),
      b2,
    ]),
  );

  print('');
  print('Test 4 - Invalid encodings:');
  _check(
    'short signature rejected',
    !BatchVerify.verify([
      SignatureBundle(
          message: b1.message,
          signature: b1.signature.sublist(0, 63),
          publicKey: b1.publicKey),
      b2,
    ]),
  );
  _check(
    'long signature rejected',
    !BatchVerify.verify([
      SignatureBundle(
          message: b1.message,
          signature: Uint8List.fromList([...b1.signature, 0]),
          publicKey: b1.publicKey),
      b2,
    ]),
  );
  _check(
    'invalid public key rejected',
    !BatchVerify.verify([
      SignatureBundle(
          message: b1.message,
          signature: b1.signature,
          publicKey: Uint8List(32)),
      b2,
    ]),
  );

  print('');
  print('Test 5 - Throughput (10 signatures):');
  final ten =
      List.generate(10, (i) => _bundle(i * 7 + 1, 'Command $i — fire!'));

  final stopwatch = Stopwatch()..start();
  final batchResult = BatchVerify.verify(ten);
  final batchTime = stopwatch.elapsedMilliseconds;

  stopwatch.reset();
  stopwatch.start();
  final individualResult =
      ten.every((b) => XEdDSA.verify(b.message, b.signature, b.publicKey));
  final individualTime = stopwatch.elapsedMilliseconds;

  _check('individual verification agrees', individualResult);
  _check('batch verification agrees', batchResult);
  print('  individual time: $individualTime ms');
  print('  batch time:      $batchTime ms');

  print('');
  print('=== Results: $_passed passed, $_failed failed ===');
}
