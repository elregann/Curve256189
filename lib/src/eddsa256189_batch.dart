// eddsa256189_batch.dart

// Batch verification of Ed256189 signatures.
//
// For each signature choose a random non-zero scalar z_i and accumulate:
//
//   LHS = (sum z_i*S_i) * B
//   RHS = sum (z_i * R_i) + sum (z_i*k_i * A_i)
//
// The batch is valid iff LHS == RHS as full points. Every input receives the
// same strict validation as individual verification: 65-byte signatures,
// canonical S < n, canonical 33-byte point encodings, and non-identity
// prime-order subgroup membership for both R and A.

import 'dart:typed_data';

import 'eddsa256189.dart';
import 'eddsa256189_internal.dart';
import 'montgomery.dart';
import 'params.dart';

// Container for a single Ed256189 signature verification unit.
// message:   original message that was signed
// signature: 65 bytes — R (33 bytes) || S (32 bytes, little-endian)
// publicKey: 33 bytes — encoded A
class Ed256189SignatureBundle {
  final Uint8List message;
  final Uint8List signature;
  final Uint8List publicKey;

  Ed256189SignatureBundle({
    required this.message,
    required this.signature,
    required this.publicKey,
  });
}

class Ed256189BatchVerify {
  static final BigInt _n = Curve256189Params.n;
  static final MontgomeryPoint _basePoint = MontgomeryPoint.G;

  // Batch verify a list of signatures.
  // Returns true if ALL signatures are valid; false if ANY is invalid.
  static bool verify(List<Ed256189SignatureBundle> bundles) {
    if (bundles.isEmpty) return true;

    if (bundles.length == 1) {
      final b = bundles[0];
      return Ed256189.verify(b.message, b.signature, b.publicKey);
    }

    final scalars = <BigInt>[];
    final points = <MontgomeryPoint>[];
    BigInt lhsScalar = BigInt.zero;

    for (final bundle in bundles) {
      final input = parseEd256189Input(bundle.signature, bundle.publicKey);
      if (input == null) return false;

      final k = Ed256189.challengeFor(
        input.rEncoded,
        bundle.publicKey,
        bundle.message,
      );

      // Random non-zero batch scalar prevents forgery via cancellation.
      final z = Montgomery.randomScalar();

      lhsScalar = (lhsScalar + z * input.s) % _n;
      scalars.add(z);
      points.add(input.rMontgomery);
      scalars.add((z * k) % _n);
      points.add(input.publicMontgomery);
    }

    final lhs = Montgomery.scalarMulFull(lhsScalar, _basePoint);
    final rhs = Montgomery.multiScalarMul(scalars, points);
    return Montgomery.pointsEqual(lhs, rhs);
  }
}
