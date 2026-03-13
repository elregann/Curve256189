// batch_verify.dart
// Batch verification of Ed256189 signatures
// Based on batch verification technique by Daniel J. Bernstein (2012)
// Formalized for Edwards curves by Henry de Valence et al. (2017)
// "Batch Verification of Ed25519 Signatures"
// Adapted for Curve256189 by Ismael Urzaiz Aranda (2026)
import 'dart:typed_data';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'params.dart';
import 'edwards.dart';
import 'eddsa.dart';
import 'montgomery.dart';

// Container for a single signature verification unit
// message:   original message that was signed
// signature: 65 bytes — R (33 bytes compressed) || s (32 bytes little-endian)
// publicKey: 33 bytes compressed Edwards point
class SignatureBundle {
  final Uint8List message;
  final Uint8List signature;
  final Uint8List publicKey;

  SignatureBundle({
    required this.message,
    required this.signature,
    required this.publicKey,
  });
}

class BatchVerify {
  static final BigInt _n = Curve256189Params.n;

  // Base point G in Twisted Edwards coordinates — must match EdDSA
  static final EdwardsPoint g_ = TwistedEdwards.fromMontgomery(
    MontgomeryPoint.G,
  );

  // Batch verify n signatures in a single operation
  // Returns true if ALL signatures are valid
  // Returns false if ANY signature is invalid
  //
  // Algorithm (Bernstein 2012):
  // For each signature i, choose random scalar zi and compute:
  //   lhs = sum(zi * si) * G
  //   rhs = sum(zi * Ri + zi * hi * PKi)
  // Valid iff lhs == rhs
  //
  // Security: random zi prevents forgery via linear combination
  // Speedup:  ~1.5x-2x over individual verify for large batches
  static bool verify(List<SignatureBundle> bundles) {
    if (bundles.isEmpty) return true;

    // Single signature — fall back to individual verify
    if (bundles.length == 1) {
      final b = bundles[0];
      return EdDSA.verify(b.message, b.signature, b.publicKey);
    }

    final rng = Random.secure();

    // Accumulate batch equation:
    // lhsScalar = sum(zi * si) mod n
    // rhs       = sum(zi * Ri + zi * hi * PKi)
    BigInt lhsScalar = BigInt.zero;
    EdwardsPoint? rhs;

    for (final bundle in bundles) {
      // Decode signature: R (33 bytes) || s (32 bytes)
      final rBytes = bundle.signature.sublist(0, 33);
      final sBytes = bundle.signature.sublist(33, 65);

      // Decode s — little-endian 32 bytes
      BigInt s = BigInt.zero;
      for (int i = 0; i < 32; i++) {
        s += BigInt.from(sBytes[i]) << (8 * i);
      }
      s = s % _n;

      // Decode commitment point R
      final R = TwistedEdwards.decodePoint(rBytes);
      if (R == null) return false;

      // Decode public key point
      final pk = TwistedEdwards.decodePoint(bundle.publicKey);
      if (pk == null) return false;

      // Compute challenge hash: h = SHA-512(R || pk || message) mod n
      // Uses full 64 bytes of SHA-512 output for uniform distribution
      final hHash = sha512.convert([
        ...rBytes,
        ...bundle.publicKey,
        ...bundle.message,
      ]).bytes;
      BigInt h = BigInt.zero;
      for (int i = 0; i < 64; i++) {
        h += BigInt.from(hHash[i]) << (8 * i);
      }
      h = h % _n;

      // Random batch scalar zi (128-bit) — prevents forgery via linear combination
      BigInt z = BigInt.zero;
      for (int i = 0; i < 4; i++) {
        z = (z << 32) + BigInt.from(rng.nextInt(0xFFFFFFFF));
      }
      z = z % _n;

      // Accumulate lhs: sum(zi * si) mod n
      lhsScalar = (lhsScalar + z * s) % _n;

      // Accumulate rhs: zi*Ri + zi*hi*PKi
      final ziR    = TwistedEdwards.scalarMul(z, R);
      final ziHPk  = TwistedEdwards.scalarMul((z * h) % _n, pk);
      final contrib = TwistedEdwards.add(ziR, ziHPk);

      rhs = rhs == null ? contrib : TwistedEdwards.add(rhs, contrib);
    }

    // Final check: sum(zi*si)*G == sum(zi*Ri + zi*hi*PKi)
    final lhs = TwistedEdwards.scalarMul(lhsScalar, g_);
    return lhs.x == rhs!.x && lhs.y == rhs.y;
  }
}