// x256189.dart

// X256189 — Elliptic Curve Diffie-Hellman key exchange
// Based on Curve256189 Montgomery curve over 2²⁵⁶ - 189
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'montgomery.dart';
import 'params.dart';

class X256189 {
  static final BigInt p = Curve256189Params.p;
  static final BigInt n = Curve256189Params.n;

  static const int _seedLength = 32;
  static const int _publicKeyLength = 32;

  // Little-endian encoding per RFC 7748 (X25519 convention)
  static Uint8List _bigIntToBytes(BigInt value) {
    final bytes = Uint8List(32);
    var v = value;
    for (int i = 0; i < 32; i++) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }

  // Convert 32-byte little-endian array to BigInt
  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = result | (BigInt.from(bytes[i]) << (8 * i));
    }
    return result;
  }

  // Derive the cofactor-cleared private scalar from a 32-byte seed.
  static BigInt _privateScalar(Uint8List seed) {
    if (seed.length != _seedLength) {
      throw ArgumentError.value(
        seed.length,
        'seed',
        'X256189 requires exactly $_seedLength bytes',
      );
    }

    final h = sha512.convert(seed).bytes;
    final skBytes = Uint8List.fromList(h.sublist(0, 32));
    skBytes[0] &= 252;
    skBytes[31] &= 127;
    skBytes[31] |= 64;

    final sk = _bytesToBigInt(skBytes) % n;

    // Cofactor clearing per RFC 7748: multiply scalar by h=4.
    // Ensures the shared secret lies in the prime-order subgroup.
    return (sk * BigInt.from(4)) % n;
  }

  // Generate X256189 key pair from 32-byte seed
  // Returns {privateKey: 32 bytes, publicKey: 32 bytes}
  static Map<String, Uint8List> generateKeyPair(Uint8List seed) {
    final skCleared = _privateScalar(seed);

    final pkX = Montgomery.ladderXOnly(skCleared, MontgomeryPoint.G.x);
    if (pkX == null) {
      throw StateError('derived the point at infinity as public key');
    }

    return {
      'privateKey': Uint8List.fromList(seed),
      'publicKey': _bigIntToBytes(pkX),
    };
  }

  // Compute ECDH shared secret.
  // Returns a 32-byte shared secret x-coordinate, or null if the public key
  // is malformed, off-curve, low-order, or not in the prime-order subgroup.
  static Uint8List? computeSharedSecret(
      Uint8List privateKey, Uint8List publicKeyBytes) {
    if (publicKeyBytes.length != _publicKeyLength) return null;

    final skCleared = _privateScalar(privateKey);

    final pkX = _bytesToBigInt(publicKeyBytes);
    if (pkX <= BigInt.zero || pkX >= p) return null;

    // Decode as the canonical even-y point and require prime-order subgroup
    // membership. This rejects low-order and mixed-order public keys.
    final pkPoint = Montgomery.pointFromX(pkX, evenY: true);
    if (pkPoint == null) return null;
    if (!Montgomery.isInPrimeOrderSubgroup(pkPoint)) return null;

    final sharedX = Montgomery.ladderXOnly(skCleared, pkX);
    if (sharedX == null || sharedX == BigInt.zero) return null;

    return _bigIntToBytes(sharedX);
  }
}
