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
    for (int i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) | BigInt.from(bytes[i]);
    }
    return result;
  }

  // Encode titik Edwards → 32 bytes
  static Uint8List _encodePoint(EdwardsPoint P) {
    return TwistedEdwards.encodePoint(P);
  }

  // Key Generation
  static Map<String, Uint8List> generateKeyPair(Uint8List seed) {
    // Hash seed → 64 bytes
    final h = _hash(seed);

    // Clamp private key (32 bytes pertama)
    final skBytes = h.sublist(0, 32);
    skBytes[0] &= 248;   // clear 3 bit terbawah
    skBytes[31] &= 127;  // clear bit tertinggi
    skBytes[31] |= 64;   // set bit kedua tertinggi

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

    // Signature = R || S (64 bytes)
    return Uint8List.fromList([...rBytes, ...sBytes]);
  }

  // Verify
  static bool verify(Uint8List message, Uint8List signature, Uint8List publicKeyBytes) {
    if (signature.length != 64) return false;

    // Decode R dan S dari signature
    final rBytes = signature.sublist(0, 32);
    final sBytes = signature.sublist(32, 64);
    final S = _bytesToBigInt(sBytes);

    // S harus dalam range [0, n)
    if (S >= n) return false;

    // Decode titik R dari signature
    final R = TwistedEdwards.decodePoint(rBytes);
    if (R == null) return false;

    // Decode public key
    final pk = TwistedEdwards.decodePoint(publicKeyBytes);
    if (pk == null) return false;

    // Verifikasi public key on curve
    if (!TwistedEdwards.isOnCurve(pk)) return false;

    // Hash(R + pk + message)
    final hHash = _hash(Uint8List.fromList([...rBytes, ...publicKeyBytes, ...message]));
    final hInt = _bytesToBigInt(hHash) % n;

    // Cek: S*G == R + h*pk
    final sg = TwistedEdwards.scalarMul(S, G);
    final hPk = TwistedEdwards.scalarMul(hInt, pk);
    final rhPk = TwistedEdwards.add(R, hPk);

    return sg.x == rhPk.x && sg.y == rhPk.y;
  }
}