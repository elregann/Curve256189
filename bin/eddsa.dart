import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'edwards.dart';
import 'montgomery.dart';
import 'params.dart';

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

    final sk = _bytesToBigInt(skBytes) % n;

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
    final sk = _bytesToBigInt(skBytes) % n;

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
  static bool verify(Uint8List message, Uint8List signature, Uint8List publicKeyBytes) {
    if (signature.length != 65) return false;

    final rBytes = signature.sublist(0, 33);
    final sBytes = signature.sublist(33, 65);
    final S = _bytesToBigInt(sBytes);

    if (S >= n) return false;

    // Decode R point and public key
    final R = TwistedEdwards.decodePoint(rBytes);
    if (R == null) return false;

    final pk = TwistedEdwards.decodePoint(publicKeyBytes);
    if (pk == null) return false;

    if (!TwistedEdwards.isOnCurve(pk)) return false;

    // Verification: S * G == R + hash(R + pk + message) * pk
    final hHash = _hash(Uint8List.fromList([...rBytes, ...publicKeyBytes, ...message]));
    final hInt = _bytesToBigInt(hHash) % n;

    final sg = TwistedEdwards.scalarMul(S, G);
    final hPk = TwistedEdwards.scalarMul(hInt, pk);
    final rhPk = TwistedEdwards.add(R, hPk);

    return sg.x == rhPk.x && sg.y == rhPk.y;
  }
}