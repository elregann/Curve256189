import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'edwards.dart';
import 'montgomery.dart';
import 'params.dart';

class EdDSA {
  static final BigInt p = Curve256189Params.p;
  static final BigInt n = Curve256189Params.n;

  // Base point G dalam Twisted Edwards
  static final EdwardsPoint G = TwistedEdwards.fromMontgomery(
    MontgomeryPoint.G,
  );

  // Hash helper — SHA-512
  static Uint8List _hash(Uint8List data) {
    final digest = sha512.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  // Konversi BigInt → bytes (32 bytes, little-endian)
  static Uint8List _bigIntToBytes(BigInt value) {
    final bytes = Uint8List(32);
    var v = value;
    for (int i = 0; i < 32; i++) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }

  // Konversi bytes → BigInt (little-endian)
  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (int i = 0; i < bytes.length; i++) {
      result = result | (BigInt.from(bytes[i]) << (8 * i));
    }
    return result;
  }

  // Encode titik Edwards → 33 bytes
  static Uint8List _encodePoint(EdwardsPoint P) {
    return TwistedEdwards.encodePoint(P);
  }

  // Key Generation
  static Map<String, Uint8List> generateKeyPair(Uint8List seed) {
    // Hash seed → 64 bytes
    final h = _hash(seed);

    // Clamp private key (32 bytes pertama)
    final skBytes = h.sublist(0, 32);
    skBytes[0] &= 248;  // clear 3 bit terbawah
    skBytes[31] &= 127; // clear bit tertinggi
    skBytes[31] |= 64;  // set bit kedua tertinggi

    final sk = _bytesToBigInt(skBytes) % n;

    // Public key = sk * G
    final pk = TwistedEdwards.scalarMul(sk, G);
    final pkBytes = _encodePoint(pk);

    return {
      'privateKey': seed,
      'publicKey': pkBytes,
    };
  }

  // Sign
  static Uint8List sign(Uint8List message, Uint8List privateKey) {
    // Hash private key
    final h = _hash(privateKey);
    final skBytes = h.sublist(0, 32);
    skBytes[0] &= 248;
    skBytes[31] &= 127;
    skBytes[31] |= 64;
    final sk = _bytesToBigInt(skBytes) % n;

    // Public key
    final pkPoint = TwistedEdwards.scalarMul(sk, G);
    final pkBytes = _encodePoint(pkPoint);

    // r = hash(prefix + message) mod n
    final prefix = h.sublist(32, 64);
    final rHash = _hash(Uint8List.fromList([...prefix, ...message]));
    final r = _bytesToBigInt(rHash) % n;

    // R = r * G
    final R = TwistedEdwards.scalarMul(r, G);
    final rBytes = _encodePoint(R);

    // S = (r + hash(R + pk + message) * sk) mod n
    final sHash = _hash(Uint8List.fromList([...rBytes, ...pkBytes, ...message]));
    final hInt = _bytesToBigInt(sHash) % n;
    final S = (r + hInt * sk) % n;
    final sBytes = _bigIntToBytes(S);

    // Signature = R(33) || S(32) = 65 bytes
    return Uint8List.fromList([...rBytes, ...sBytes]);
  }

  // Verify
  static bool verify(Uint8List message, Uint8List signature, Uint8List publicKeyBytes) {
    if (signature.length != 65) return false; // 33 (R) + 32 (S)

    final rBytes = signature.sublist(0, 33);
    final sBytes = signature.sublist(33, 65);
    final S = _bytesToBigInt(sBytes);

    if (S >= n) return false;

    final R = TwistedEdwards.decodePoint(rBytes);
    if (R == null) return false;

    final pk = TwistedEdwards.decodePoint(publicKeyBytes);
    if (pk == null) return false;

    if (!TwistedEdwards.isOnCurve(pk)) return false;

    final hHash = _hash(Uint8List.fromList([...rBytes, ...publicKeyBytes, ...message]));
    final hInt = _bytesToBigInt(hHash) % n;

    final sg = TwistedEdwards.scalarMul(S, G);
    final hPk = TwistedEdwards.scalarMul(hInt, pk);
    final rhPk = TwistedEdwards.add(R, hPk);

    return sg.x == rhPk.x && sg.y == rhPk.y;
  }
}