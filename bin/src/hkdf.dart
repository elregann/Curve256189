// hkdf.dart
// HKDF key derivation per RFC 5869
// Used to derive symmetric keys from ECDH shared secret
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class HKDF {
  // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
  static Uint8List extract(Uint8List salt, Uint8List ikm) {
    final hmacSha256 = Hmac(sha256, salt);
    final digest = hmacSha256.convert(ikm);
    return Uint8List.fromList(digest.bytes);
  }

  // HKDF-Expand: OKM = T(1) || T(2) || ...
  static Uint8List expand(Uint8List prk, Uint8List info, int length) {
    final okm = <int>[];
    var t = <int>[];
    var i = 1;
    while (okm.length < length) {
      final hmacSha256 = Hmac(sha256, prk);
      final input = Uint8List.fromList([...t, ...info, i]);
      t = hmacSha256.convert(input).bytes;
      okm.addAll(t);
      i++;
    }
    return Uint8List.fromList(okm.sublist(0, length));
  }

  // HKDF: Extract + Expand
  // ikm: input key material (shared secret)
  // salt: optional, defaults to 'Curve256189'
  // info: context string
  // length: output key length in bytes
  static Uint8List derive({
    required Uint8List ikm,
    Uint8List? salt,
    required Uint8List info,
    int length = 32,
  }) {
    final effectiveSalt = salt ??
        Uint8List.fromList('Curve256189'.codeUnits);
    final prk = extract(effectiveSalt, ikm);
    return expand(prk, info, length);
  }
}