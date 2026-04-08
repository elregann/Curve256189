// aesgcm.dart

// AES-256-GCM authenticated encryption per NIST SP 800-38D
// Provides confidentiality + integrity + authenticity in a single pass
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

// Result of AES-GCM encryption
// ciphertext: encrypted data (same length as plaintext)
// tag:        16-byte authentication tag for integrity verification
class AESGCMResult {
  final Uint8List ciphertext;
  final Uint8List tag;

  AESGCMResult({required this.ciphertext, required this.tag});
}

class AESGCM {
  // Encrypt plaintext with AES-256-GCM
  // key:       32 bytes (256-bit) — derive via HKDF from ECDH shared secret
  // nonce:     12 bytes (96-bit) per NIST SP 800-38D — must be unique per key
  // plaintext: arbitrary length
  // aad:       optional additional authenticated data (authenticated but not encrypted)
  // Returns:   AESGCMResult with ciphertext + 16-byte authentication tag
  static AESGCMResult encrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    Uint8List? aad,
  }) {
    assert(key.length == 32, 'Key must be 32 bytes (AES-256)');
    assert(nonce.length == 12, 'Nonce must be 12 bytes per NIST SP 800-38D');

    final cipher = GCMBlockCipher(AESEngine());
    final params = AEADParameters(
      KeyParameter(key),
      128, // tag size in bits (128-bit = 16 bytes)
      nonce,
      aad ?? Uint8List(0),
    );

    cipher.init(true, params); // true = encrypt mode

    // Allocate output buffer: plaintext length + 16 bytes for tag
    final output = Uint8List(plaintext.length + 16);
    var offset = 0;
    if (plaintext.isNotEmpty) {
      offset = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
    }
    // Flush remaining bytes and append authentication tag
    offset += cipher.doFinal(output, offset);

    // Split output: ciphertext || tag
    final ciphertext = output.sublist(0, offset - 16);
    final tag = output.sublist(offset - 16, offset);

    return AESGCMResult(ciphertext: ciphertext, tag: tag);
  }

  // Decrypt and verify AES-256-GCM ciphertext
  // key:        32 bytes — must match encryption key
  // nonce:      12 bytes — must match encryption nonce
  // ciphertext: encrypted data
  // tag:        16-byte authentication tag from encryption
  // aad:        must match AAD used during encryption (if any)
  // Returns:    plaintext if tag verification succeeds, null otherwise
  static Uint8List? decrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
    Uint8List? aad,
  }) {
    assert(key.length == 32, 'Key must be 32 bytes (AES-256)');
    assert(nonce.length == 12, 'Nonce must be 12 bytes per NIST SP 800-38D');
    assert(tag.length == 16, 'Tag must be 16 bytes (128-bit)');

    final cipher = GCMBlockCipher(AESEngine());
    final params = AEADParameters(
      KeyParameter(key),
      128,
      nonce,
      aad ?? Uint8List(0),
    );

    cipher.init(false, params); // false = decrypt mode

    // pointycastle GCM decrypt expects ciphertext || tag as input
    final input = Uint8List.fromList([...ciphertext, ...tag]);
    final output = Uint8List(cipher.getOutputSize(input.length));

    try {
      var offset = cipher.processBytes(input, 0, input.length, output, 0);
      offset += cipher.doFinal(output, offset);
      return output.sublist(0, offset);
    } on InvalidCipherTextException {
      // Authentication tag mismatch — ciphertext or AAD was tampered
      return null;
    } catch (e) {
      return null;
    }
  }
}