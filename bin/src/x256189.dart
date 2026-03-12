// x256189.dart
// X256189 — Elliptic Curve Diffie-Hellman key exchange
// Based on Curve256189 Montgomery curve over 2²⁵⁶ - 189
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'montgomery.dart';
import 'params.dart';
import 'field.dart';

class X256189 {
  static final BigInt p = Curve256189Params.p;
  static final BigInt n = Curve256189Params.n;

  // Convert BigInt to 32-byte big-endian array
  static Uint8List _bigIntToBytes(BigInt value) {
    final bytes = Uint8List(32);
    var v = value;
    for (int i = 31; i >= 0; i--) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }

  // Convert 32-byte big-endian array to BigInt
  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  // Generate X256189 key pair from 32-byte seed
  // Returns {privateKey: 32 bytes, publicKey: 32 bytes}
  static Map<String, Uint8List> generateKeyPair(Uint8List seed) {
    // Derive private scalar via SHA-512 + clamp
    final h = sha512.convert(seed).bytes;
    final skBytes = Uint8List.fromList(h.sublist(0, 32));
    skBytes[0] &= 248;
    skBytes[31] &= 127;
    skBytes[31] |= 64;

    final sk = _bytesToBigInt(skBytes) % n;

    // Public key: sk * G (x-coordinate only)
    final pkX = Montgomery.ladderXOnly(sk, MontgomeryPoint.G.x);
    final pkBytes = _bigIntToBytes(pkX);

    return {
      'privateKey': seed,
      'publicKey': pkBytes,
    };
  }

  // Compute ECDH shared secret
  // Returns 32-byte shared secret x-coordinate
  static Uint8List? computeSharedSecret(
      Uint8List privateKey, Uint8List publicKeyBytes) {
    // Derive private scalar
    final h = sha512.convert(privateKey).bytes;
    final skBytes = Uint8List.fromList(h.sublist(0, 32));
    skBytes[0] &= 248;
    skBytes[31] &= 127;
    skBytes[31] |= 64;

    final sk = _bytesToBigInt(skBytes) % n;

    // Decode and validate public key
    final pkX = _bytesToBigInt(publicKeyBytes);
    if (pkX == BigInt.zero || pkX >= p) return null;

    // Recover y for validation
    final x2 = FieldElement.mul(pkX, pkX);
    final x3 = FieldElement.mul(pkX, x2);
    final rhs = FieldElement.add(
      FieldElement.add(x3, FieldElement.mul(Curve256189Params.A, x2)),
      pkX,
    );
    final exp = (p + BigInt.one) >> 2;
    final y = FieldElement.pow(rhs, exp);
    if (FieldElement.mul(y, y) != rhs) return null;

    // Validate public key point
    final pkPoint = MontgomeryPoint(pkX, y);
    if (!Montgomery.isValidPoint(pkPoint)) return null;

    // Compute shared secret: sk * pk (x-coordinate only)
    final sharedX = Montgomery.ladderXOnly(sk, pkX);
    if (sharedX == BigInt.zero) return null;

    return _bigIntToBytes(sharedX);
  }
}