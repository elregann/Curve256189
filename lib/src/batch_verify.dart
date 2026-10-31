// batch_verify.dart

// Batch verification of XEdDSA signatures on Curve256189.
//
// For each signature choose a random non-zero scalar z_i and accumulate:
//
//   LHS = (sum z_i*s_i) * G
//   RHS = sum (z_i * R_i) + sum (z_i*h_i * P_i)
//
// The batch is valid iff LHS == RHS as full points. Every input receives the
// same strict validation as individual verification: 64-byte signatures,
// canonical s < n, canonical even-y x-coordinates, and prime-order subgroup
// membership for both R and P.

import 'dart:typed_data';

import 'montgomery.dart';
import 'params.dart';
import 'xeddsa.dart';

// Container for a single signature verification unit.
// message:   original message that was signed
// signature: 64 bytes — x(R) (32 bytes) || s (32 bytes, little-endian)
// publicKey: 32 bytes — x(P) (little-endian)
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
  static final MontgomeryPoint _basePoint = MontgomeryPoint.G;

  // Batch verify a list of signatures.
  // Returns true if ALL signatures are valid; false if ANY is invalid.
  static bool verify(List<SignatureBundle> bundles) {
    if (bundles.isEmpty) return true;

    if (bundles.length == 1) {
      final b = bundles[0];
      return XEdDSA.verify(b.message, b.signature, b.publicKey);
    }

    final scalars = <BigInt>[];
    final points = <MontgomeryPoint>[];
    BigInt lhsScalar = BigInt.zero;

    for (final bundle in bundles) {
      if (bundle.signature.length != XEdDSA.signatureLength) return false;
      if (bundle.publicKey.length != XEdDSA.publicKeyLength) return false;

      final xR = Uint8List.fromList(bundle.signature.sublist(0, 32));
      final s = XEdDSA.decodeLittleEndian(
        Uint8List.fromList(bundle.signature.sublist(32, 64)),
      );

      if (s >= _n) return false;

      final R = Montgomery.pointFromX(
        XEdDSA.decodeLittleEndian(xR),
        evenY: true,
      );
      if (R == null) return false;
      if (!Montgomery.isInPrimeOrderSubgroup(R)) return false;

      final P = Montgomery.pointFromX(
        XEdDSA.decodeLittleEndian(bundle.publicKey),
        evenY: true,
      );
      if (P == null) return false;
      if (!Montgomery.isInPrimeOrderSubgroup(P)) return false;

      final h = XEdDSA.challengeFor(
        xR,
        bundle.publicKey,
        bundle.message,
      );

      // Random non-zero batch scalar prevents forgery via cancellation.
      final z = Montgomery.randomScalar();

      lhsScalar = (lhsScalar + z * s) % _n;
      scalars.add(z);
      points.add(R);
      scalars.add((z * h) % _n);
      points.add(P);
    }

    final lhs = Montgomery.scalarMulFull(lhsScalar, _basePoint);
    final rhs = Montgomery.multiScalarMul(scalars, points);
    return Montgomery.pointsEqual(lhs, rhs);
  }
}
