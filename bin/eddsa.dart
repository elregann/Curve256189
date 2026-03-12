import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'edwards.dart';
import 'montgomery.dart';
import 'params.dart';
import 'hfe.dart';
import 'field.dart';

class EdDSA {
  static final BigInt p = Curve256189Params.p;
  static final BigInt n = Curve256189Params.n;

  // Base point G in Twisted Edwards coordinates
  static final EdwardsPoint G = TwistedEdwards.fromMontgomery(
    MontgomeryPoint.G,
  );

  // SHA-512 hash function for message and key derivation
  static Uint8List _hash(Uint8List data) {
    final digest = sha512.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  // Convert BigInt to 32-byte little-endian array
  static Uint8List _bigIntToBytes(BigInt value) {
    final bytes = Uint8List(32);
    var v = value;
    for (int i = 0; i < 32; i++) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }

  // Convert little-endian byte array to BigInt
  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = result | (BigInt.from(bytes[i]) << (8 * i));
    }
    return result;
  }

  // Encode Edwards point to 33-byte compressed format
  static Uint8List _encodePoint(EdwardsPoint P) {
    return TwistedEdwards.encodePoint(P);
  }

  // Generate EdDSA key pair from 32-byte seed
  static Map<String, Uint8List> generateKeyPair(Uint8List seed) {
    // Hash seed and clamp private key bytes
    final h = _hash(seed);
    final skBytes = h.sublist(0, 32);
    skBytes[0] &= 248;
    skBytes[31] &= 127;
    skBytes[31] |= 64;

    final skRaw = _bytesToBigInt(skBytes) % n;
    final constants = HFE.deriveConstants(seed);
    final sk = HFE.wrap(
      skRaw,
      constants['a']!,
      constants['b']!,
      constants['c']!,
      constants['d']!,
      constants['coeff']!,
    );

    // Public key computation: pk = sk * G
    final pk = TwistedEdwards.scalarMul(sk, G);
    final pkBytes = _encodePoint(pk);

    return {
      'privateKey': seed,
      'publicKey': pkBytes,
    };
  }

  // Create deterministic EdDSA signature
  static Uint8List sign(Uint8List message, Uint8List privateKey) {
    // Derive secret scalar from private key
    final h = _hash(privateKey);
    final skBytes = h.sublist(0, 32);
    skBytes[0] &= 248;
    skBytes[31] &= 127;
    skBytes[31] |= 64;

    final skRaw = _bytesToBigInt(skBytes) % n;
    final constants = HFE.deriveConstants(privateKey);
    final sk = HFE.wrap(
      skRaw,
      constants['a']!,
      constants['b']!,
      constants['c']!,
      constants['d']!,
      constants['coeff']!,
    );

    // Generate public key for hashing
    final pkPoint = TwistedEdwards.scalarMul(sk, G);
    final pkBytes = _encodePoint(pkPoint);

    // Deterministic nonce r = hash(prefix + message)
    final prefix = h.sublist(32, 64);
    final rHash = _hash(Uint8List.fromList([...prefix, ...message]));
    final r = _bytesToBigInt(rHash) % n;

    // Commitment R = r * G
    final R = TwistedEdwards.scalarMul(r, G);
    final rBytes = _encodePoint(R);

    // Scalar S = (r + hash(R + pk + message) * sk) mod n
    final sHash = _hash(Uint8List.fromList([...rBytes, ...pkBytes, ...message]));
    final hInt = _bytesToBigInt(sHash) % n;
    final S = (r + hInt * sk) % n;
    final sBytes = _bigIntToBytes(S);

    // Signature format: R (33 bytes) || S (32 bytes)
    return Uint8List.fromList([...rBytes, ...sBytes]);
  }

  // Verify EdDSA signature validity
  // Uses Montgomery x-only arithmetic to avoid Edwards add() canonical y issues
  // Verification equation: S*G == R + hash(R || pk || message) * pk
  // Implemented via Montgomery affine add with both y-candidate combinations
  static bool verify(Uint8List message, Uint8List signature, Uint8List publicKeyBytes) {
    if (signature.length != 65) return false;

    final rBytes = signature.sublist(0, 33);
    final sBytes = signature.sublist(33, 65);
    final S = _bytesToBigInt(sBytes);

    if (S >= n) return false;

    // Decode R point and public key from compressed bytes
    final R = TwistedEdwards.decodePoint(rBytes);
    if (R == null) return false;

    final pk = TwistedEdwards.decodePoint(publicKeyBytes);
    if (pk == null) return false;

    if (!TwistedEdwards.isOnCurve(pk)) return false;

    // Compute challenge hash: h = SHA512(R || pk || message) mod n
    final hHash = _hash(Uint8List.fromList([...rBytes, ...publicKeyBytes, ...message]));
    final hInt = _bytesToBigInt(hHash) % n;

    // Compute S*G and h*pk via Montgomery x-only ladder
    final sgX = Montgomery.ladderXOnly(S, MontgomeryPoint.G.x);
    final pkMontX = TwistedEdwards.toMontgomery(pk).x;
    final hPkX = Montgomery.ladderXOnly(hInt, pkMontX);
    final rMontX = TwistedEdwards.toMontgomery(R).x;

    // Recover y candidates from Montgomery curve equation: y² = x³ + Ax² + x
    BigInt recoverY(BigInt x) {
      final x2 = (x * x) % p;
      final x3 = (x * x2) % p;
      final rhs = (x3 + Montgomery.A * x2 + x) % p;
      final exp = (p + BigInt.one) >> 2;
      return rhs.modPow(exp, p);
    }

    // Try both y-candidate combinations for R and h*pk
    // Valid signature satisfies one of: (rY, hYn) or (rYn, hY)
    final rY  = recoverY(rMontX);
    final rYn = FieldElement.sub(BigInt.zero, rY);
    final hY  = recoverY(hPkX);
    final hYn = FieldElement.sub(BigInt.zero, hY);

    final s2 = Montgomery.add(MontgomeryPoint(rMontX, rY),  MontgomeryPoint(hPkX, hYn)).x;
    final s3 = Montgomery.add(MontgomeryPoint(rMontX, rYn), MontgomeryPoint(hPkX, hY)).x;

    return s2 == sgX || s3 == sgX;
  }
}