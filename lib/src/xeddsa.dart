// xeddsa.dart

// XEdDSA — x-only Schnorr-style signatures on Curve256189.
//
// Design
// ------
// The public key is the 32-byte little-endian Montgomery x-coordinate of
// P = [a]G. Signatures are 64 bytes: x(R) || s.
//
// Both P and R use the canonical even-y representative. The signer adjusts
// a -> n - a and r -> n - r when necessary; this does not change x(P) or
// x(R). Verification reconstructs the canonical even-y points from x and
// checks the exact full-point equation
//
//     [s]G == R + [h]P
//
// with h = SHA-512(domain || x(R) || x(P) || message) mod n. No Edwards
// arithmetic is used anywhere in the signing or verification path.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'montgomery.dart';
import 'params.dart';
import 'xeddsa_internal.dart';

// Secret key material derived from a seed. The prefix is the second half of
// SHA-512(seed) and is used only for deterministic nonce derivation.
class _KeyMaterial {
  final BigInt scalar;
  final MontgomeryPoint point;
  final Uint8List prefix;

  const _KeyMaterial(this.scalar, this.point, this.prefix);
}

class XEdDSA {
  static final BigInt p = Curve256189Params.p;
  static final BigInt n = Curve256189Params.n;

  static const int seedLength = 32;
  static const int publicKeyLength = xeddsaPublicKeyLength;
  static const int signatureLength = xeddsaSignatureLength;

  static const int _nonceTag = 0x01;
  static const int _challengeTag = 0x02;

  static final List<int> _domain = utf8.encode('Curve256189-XEdDSA-v1');

  static final MontgomeryPoint _basePoint = MontgomeryPoint.G;

  // ---------------------------------------------------------------------
  // Encoding helpers (little-endian, RFC 7748 convention)
  // ---------------------------------------------------------------------

  static Uint8List encodeScalar(BigInt value) {
    if (value < BigInt.zero || value >= n) {
      throw ArgumentError('scalar out of range');
    }
    final out = Uint8List(32);
    var v = value;
    for (int i = 0; i < 32; i++) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return out;
  }

  static BigInt decodeLittleEndian(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  static Uint8List _encodeX(BigInt x) {
    final out = Uint8List(32);
    var v = x;
    for (int i = 0; i < 32; i++) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return out;
  }

  static Uint8List _hash(List<int> data) {
    return Uint8List.fromList(sha512.convert(data).bytes);
  }

  // ---------------------------------------------------------------------
  // Key derivation
  // ---------------------------------------------------------------------

  static Uint8List _checkSeed(Uint8List seed) {
    if (seed.length != seedLength) {
      throw ArgumentError.value(
        seed.length,
        'seed',
        'XEdDSA requires exactly $seedLength bytes',
      );
    }
    return seed;
  }

  // Expand a seed into the secret scalar and the nonce prefix.
  // The scalar is cofactor-cleared (a0 = 4*sk mod n) so that the public key
  // matches X256189.generateKeyPair(seed)['publicKey'].
  static List<Object> _expandSeed(Uint8List seed) {
    _checkSeed(seed);

    final digest = _hash(seed);
    final skBytes = Uint8List.fromList(digest.sublist(0, 32));
    skBytes[0] &= 252;
    skBytes[31] &= 127;
    skBytes[31] |= 64;

    var sk = decodeLittleEndian(skBytes) % n;
    if (sk == BigInt.zero) sk = BigInt.one;

    final a0 = (sk * BigInt.from(4)) % n;
    final prefix = Uint8List.fromList(digest.sublist(32, 64));
    return [a0, prefix];
  }

  // Canonicalise a scalar/point pair so that the point has an even y.
  // Returns [scalar, point].
  static List<Object> _canonicalise(BigInt scalar, MontgomeryPoint point) {
    if (point.isInfinity) {
      throw StateError('cannot canonicalise the point at infinity');
    }

    if (point.y.isEven) {
      return [scalar, point];
    }

    final adjusted = (n - (scalar % n)) % n;
    if (adjusted == BigInt.zero) {
      throw StateError('degenerate scalar while canonicalising');
    }
    return [adjusted, Montgomery.negate(point)];
  }

  // Expand the seed once and return everything signing needs: the canonical
  // even-y scalar, the canonical even-y public point, and the nonce prefix.
  static _KeyMaterial _keyMaterial(Uint8List seed) {
    final expanded = _expandSeed(seed);
    final a0 = expanded[0] as BigInt;
    final prefix = expanded[1] as Uint8List;

    final p0 = Montgomery.scalarMulFull(a0, _basePoint, blind: true);
    final canonical = _canonicalise(a0, p0);

    return _KeyMaterial(
      canonical[0] as BigInt,
      canonical[1] as MontgomeryPoint,
      prefix,
    );
  }

  // Derive x([a0]G) directly. The public key is x-only, so key generation
  // does not need the even-y canonicalisation that signing requires. This is
  // the same x-coordinate as X256189.generateKeyPair(seed)['publicKey'].
  static Uint8List _publicKeyXFromSeed(Uint8List seed) {
    final a0 = _expandSeed(seed)[0] as BigInt;

    final x = Montgomery.ladderXOnly(a0, _basePoint.x, blind: true);
    if (x == null) {
      throw StateError('derived the point at infinity as public key');
    }
    return _encodeX(x);
  }

  // Generate a key pair from a 32-byte seed.
  // Returns {privateKey: 32-byte seed, publicKey: 32-byte x(P)}.
  static Map<String, Uint8List> generateKeyPair(Uint8List seed) {
    return {
      'privateKey': Uint8List.fromList(seed),
      'publicKey': _publicKeyXFromSeed(seed),
    };
  }

  // Derive the 32-byte public key from a seed without exposing the secret
  // scalar or the nonce prefix.
  static Uint8List publicKeyFromSeed(Uint8List seed) {
    return _publicKeyXFromSeed(seed);
  }

  // ---------------------------------------------------------------------
  // Nonce and challenge derivation
  // ---------------------------------------------------------------------

  static BigInt _deriveNonce(Uint8List prefix, Uint8List message) {
    for (int counter = 0;; counter++) {
      final counterBytes = Uint8List(4)
        ..[0] = counter & 0xff
        ..[1] = (counter >> 8) & 0xff
        ..[2] = (counter >> 16) & 0xff
        ..[3] = (counter >> 24) & 0xff;

      final digest = _hash([
        ..._domain,
        _nonceTag,
        ...prefix,
        ...counterBytes,
        ...message,
      ]);

      final r = decodeLittleEndian(digest) % n;
      if (r != BigInt.zero) return r;
    }
  }

  // Public challenge helper, also used by batch verification.
  // h = SHA-512(domain || 0x02 || x(R) || x(P) || message) mod n
  static BigInt challengeFor(
    Uint8List xR,
    Uint8List xP,
    Uint8List message,
  ) {
    if (xR.length != 32 || xP.length != 32) {
      throw ArgumentError('x-coordinates must be 32 bytes');
    }
    final digest = _hash([
      ..._domain,
      _challengeTag,
      ...xR,
      ...xP,
      ...message,
    ]);
    return decodeLittleEndian(digest) % n;
  }

  // ---------------------------------------------------------------------
  // Sign
  // ---------------------------------------------------------------------

  // Deterministic signature: x(R) (32 bytes) || s (32 bytes).
  static Uint8List sign(Uint8List message, Uint8List privateKey) {
    _checkSeed(privateKey);

    final material = _keyMaterial(privateKey);
    final a = material.scalar;
    final P = material.point;
    final prefix = material.prefix;

    final r0 = _deriveNonce(prefix, message);
    final r0Point = Montgomery.scalarMulFull(r0, _basePoint, blind: true);
    final canonicalR = _canonicalise(r0, r0Point);
    final r = canonicalR[0] as BigInt;
    final R = canonicalR[1] as MontgomeryPoint;

    final xR = _encodeX(R.x);
    final xP = _encodeX(P.x);

    final h = challengeFor(xR, xP, message);
    final s = (r + h * a) % n;

    return Uint8List.fromList([...xR, ...encodeScalar(s)]);
  }

  // ---------------------------------------------------------------------
  // Verify
  // ---------------------------------------------------------------------

  static bool verify(
    Uint8List message,
    Uint8List signature,
    Uint8List publicKey,
  ) {
    final input = parseXEdDSAInput(signature, publicKey);
    if (input == null) return false;

    final h = challengeFor(input.xR, publicKey, message);

    final left = Montgomery.scalarMulFull(input.s, _basePoint);
    final hP = Montgomery.scalarMulFull(h, input.P);
    final right = Montgomery.add(input.R, hP);

    return Montgomery.pointsEqual(left, right);
  }
}
