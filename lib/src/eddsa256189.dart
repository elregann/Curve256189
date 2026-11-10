// eddsa256189.dart

// Ed256189 — an EdDSA instance for Curve256189, following the EdDSA
// algorithm of RFC 8032 on the complete twisted Edwards model E_{d,a}.
//
// Design
// ------
// RFC 8032 requires the signature curve to have a square coefficient a and a
// non-square coefficient d. The natural Edwards form of Curve256189,
//
//     E_{a,d}: a x² + y² = 1 + d x² y²,   a = 61372, d = 61368,
//
// has a non-square a and a square d, so it is not admissible. The isomorphic
// dual curve
//
//     E_{d,a}: d u² + v² = 1 + a u² v²
//
// satisfies both conditions and its standard addition law is complete. All
// arithmetic here therefore uses DualEdwards.
//
// Wire format
// -----------
// Public keys are 33 bytes: the 32-byte little-endian v-coordinate followed
// by one parity byte for u (0 or 1). p = 2^256 - 189 is a full 256-bit prime,
// so RFC 8032's 32-byte packed encoding (y plus a sign bit in the spare high
// bit) is impossible here; the sign byte is explicit instead.
//
// Signatures are 65 bytes: R (33 bytes, encoded as above) || S (32-byte
// little-endian scalar in [0, n)).
//
// This scheme is not wire-compatible with Ed25519, Ed448, or the XEdDSA
// implementation in xeddsa.dart. See doc/ed256189.md for the full
// specification and for every deliberate deviation from RFC 8032.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'eddsa256189_internal.dart';
import 'edwards.dart';
import 'montgomery.dart';
import 'params.dart';

class Ed256189 {
  static final BigInt p = Curve256189Params.p;
  static final BigInt n = Curve256189Params.n;

  static const int seedLength = 32;
  static const int publicKeyLength = ed256189PublicKeyLength;
  static const int signatureLength = ed256189SignatureLength;

  // RFC 8032 scalar pruning for a curve with cofactor 4 = 2^2 and a
  // 254-bit subgroup order: clear bits 0 and 1, clear bit 255, set bit 254.
  static const int _scalarLowMask = 0xfc;
  static const int _scalarHighClearMask = 0x7f;
  static const int _scalarHighSetMask = 0x40;

  static const int _nonceTag = 0x01;
  static const int _challengeTag = 0x02;

  static final List<int> _domain = utf8.encode('Curve256189-Ed256189-v1');

  // Generator of the prime-order subgroup on E_{d,a}: Phi(G) = (-x, 1/y).
  static final EdwardsPoint _basePoint =
      DualEdwards.fromMontgomery(MontgomeryPoint.G);

  // ---------------------------------------------------------------------
  // Encoding helpers (little-endian)
  // ---------------------------------------------------------------------

  static Uint8List _encodeScalar(BigInt value) {
    if (value < BigInt.zero || value >= n) {
      throw ArgumentError('scalar out of range');
    }
    final out = Uint8List(32);
    var v = value;
    for (var i = 0; i < 32; i++) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v >>= 8;
    }
    return out;
  }

  static BigInt _decodeLittleEndian(Uint8List bytes) {
    var result = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  static Uint8List _hash(List<int> data) {
    return Uint8List.fromList(sha512.convert(data).bytes);
  }

  static Uint8List _checkSeed(Uint8List seed) {
    if (seed.length != seedLength) {
      throw ArgumentError.value(
        seed.length,
        'seed',
        'Ed256189 requires exactly $seedLength bytes',
      );
    }
    return seed;
  }

  // ---------------------------------------------------------------------
  // Key generation
  // ---------------------------------------------------------------------

  // Expand a 32-byte seed into [scalar, prefix].
  static List<Object> _expandSeed(Uint8List seed) {
    final digest = _hash(seed);
    final scalarBytes = Uint8List.fromList(digest.sublist(0, 32));

    scalarBytes[0] &= _scalarLowMask;
    scalarBytes[31] &= _scalarHighClearMask;
    scalarBytes[31] |= _scalarHighSetMask;

    final scalar = _decodeLittleEndian(scalarBytes);
    final prefix = Uint8List.fromList(digest.sublist(32, 64));
    return [scalar, prefix];
  }

  // Returns [scalar, prefix, publicPoint].
  static List<Object> _keyMaterial(Uint8List seed) {
    final expanded = _expandSeed(seed);
    final scalar = expanded[0] as BigInt;
    final prefix = expanded[1] as Uint8List;

    final publicPoint = DualEdwards.scalarMul(
      scalar,
      _basePoint,
      blind: true,
    );
    return [scalar, prefix, publicPoint];
  }

  // Generate a key pair from a 32-byte seed.
  // Returns {privateKey: 32-byte seed, publicKey: 33-byte encoded point}.
  static Map<String, Uint8List> generateKeyPair(Uint8List seed) {
    _checkSeed(seed);
    final material = _keyMaterial(seed);
    final publicPoint = material[2] as EdwardsPoint;

    return {
      'privateKey': Uint8List.fromList(seed),
      'publicKey': DualEdwards.encodePoint(publicPoint),
    };
  }

  // Derive the 33-byte public key from a 32-byte seed.
  static Uint8List publicKeyFromSeed(Uint8List seed) {
    _checkSeed(seed);
    final material = _keyMaterial(seed);
    return DualEdwards.encodePoint(material[2] as EdwardsPoint);
  }

  // ---------------------------------------------------------------------
  // Nonce and challenge derivation
  // ---------------------------------------------------------------------

  // r = SHA-512(domain || 0x01 || prefix || counter || message) mod n.
  //
  // The counter is a defensive retry for the astronomically unlikely r = 0
  // case: r = 0 would give R = identity and make the signature degenerate.
  static BigInt _deriveNonce(Uint8List prefix, Uint8List message) {
    for (var counter = 0;; counter++) {
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

      final r = _decodeLittleEndian(digest) % n;
      if (r != BigInt.zero) return r;
    }
  }

  // Public challenge helper.
  // k = SHA-512(domain || 0x02 || R || A || message) mod n.
  static BigInt challengeFor(
    Uint8List rEncoded,
    Uint8List publicKey,
    Uint8List message,
  ) {
    if (rEncoded.length != publicKeyLength) {
      throw ArgumentError('encoded R must be $publicKeyLength bytes');
    }
    if (publicKey.length != publicKeyLength) {
      throw ArgumentError('public key must be $publicKeyLength bytes');
    }

    final digest = _hash([
      ..._domain,
      _challengeTag,
      ...rEncoded,
      ...publicKey,
      ...message,
    ]);
    return _decodeLittleEndian(digest) % n;
  }

  // ---------------------------------------------------------------------
  // Sign
  // ---------------------------------------------------------------------

  // Deterministic signature: R (33 bytes) || S (32 bytes).
  static Uint8List sign(Uint8List message, Uint8List privateKey) {
    _checkSeed(privateKey);

    final material = _keyMaterial(privateKey);
    final scalar = material[0] as BigInt;
    final prefix = material[1] as Uint8List;
    final publicPoint = material[2] as EdwardsPoint;
    final publicKey = DualEdwards.encodePoint(publicPoint);

    final r = _deriveNonce(prefix, message);
    final rPoint = DualEdwards.scalarMul(r, _basePoint, blind: true);
    final rEncoded = DualEdwards.encodePoint(rPoint);

    final k = challengeFor(rEncoded, publicKey, message);
    final s = (r + k * scalar) % n;

    return Uint8List.fromList([...rEncoded, ..._encodeScalar(s)]);
  }

  // ---------------------------------------------------------------------
  // Verify
  // ---------------------------------------------------------------------

  // Strict verification:
  //   * exact lengths, canonical point encodings, S < n
  //   * A and R must be non-identity prime-order points
  //   * exact group equation [S]B == R + [k]A (not the cofactored variant)
  static bool verify(
    Uint8List message,
    Uint8List signature,
    Uint8List publicKey,
  ) {
    final input = parseEd256189Input(signature, publicKey);
    if (input == null) return false;

    final k = challengeFor(input.rEncoded, publicKey, message);

    // Evaluate the exact group equation in the Montgomery model. B is the
    // image of Montgomery G under Phi, so its Montgomery representation is G.
    final left = Montgomery.scalarMulFull(input.s, MontgomeryPoint.G);
    final right = Montgomery.add(
      input.rMontgomery,
      Montgomery.scalarMulFull(k, input.publicMontgomery),
    );

    return Montgomery.pointsEqual(left, right);
  }
}
