// eddsa256189_internal.dart

// Shared parsing and validation for Ed256189 signatures.
//
// This file is intentionally not exported from lib/curve256189.dart. It exists
// so that individual verification and batch verification cannot drift apart:
// both must accept exactly the same set of encoded inputs.

import 'dart:typed_data';

import 'edwards.dart';
import 'montgomery.dart';
import 'params.dart';

const int ed256189PublicKeyLength = 33;
const int ed256189SignatureLength = 65;

// A signature/public-key pair that has passed every structural check:
//   * exact lengths,
//   * canonical S < n,
//   * canonical 33-byte encodings for R and A,
//   * non-identity prime-order subgroup membership for R and A.
//
// The Montgomery representations are included because both verification
// paths evaluate the group equation there. The conversion is the same
// isomorphism used by DualEdwards.isInPrimeOrderSubgroup.
class Ed256189VerifiedInput {
  final Uint8List rEncoded;
  final BigInt s;
  final EdwardsPoint rPoint;
  final EdwardsPoint publicPoint;
  final MontgomeryPoint rMontgomery;
  final MontgomeryPoint publicMontgomery;

  Ed256189VerifiedInput({
    required this.rEncoded,
    required this.s,
    required this.rPoint,
    required this.publicPoint,
    required this.rMontgomery,
    required this.publicMontgomery,
  });
}

BigInt _decodeLittleEndian(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

// Returns null for every malformed or invalid input. Never throws for byte
// strings of the wrong length or contents.
Ed256189VerifiedInput? parseEd256189Input(
  Uint8List signature,
  Uint8List publicKey,
) {
  if (signature.length != ed256189SignatureLength) return null;
  if (publicKey.length != ed256189PublicKeyLength) return null;

  final rEncoded = Uint8List.fromList(signature.sublist(0, 33));
  final s = _decodeLittleEndian(Uint8List.fromList(signature.sublist(33)));

  // S must be canonical.
  if (s >= Curve256189Params.n) return null;

  final publicPoint = DualEdwards.decodePoint(publicKey);
  if (publicPoint == null) return null;

  final rPoint = DualEdwards.decodePoint(rEncoded);
  if (rPoint == null) return null;

  // Validate subgroup membership on the Montgomery model. For points that
  // already decoded successfully this is exactly the check performed by
  // DualEdwards.isInPrimeOrderSubgroup, without converting twice.
  final publicMontgomery = DualEdwards.toMontgomery(publicPoint);
  if (!Montgomery.isInPrimeOrderSubgroup(publicMontgomery)) return null;

  final rMontgomery = DualEdwards.toMontgomery(rPoint);
  if (!Montgomery.isInPrimeOrderSubgroup(rMontgomery)) return null;

  return Ed256189VerifiedInput(
    rEncoded: rEncoded,
    s: s,
    rPoint: rPoint,
    publicPoint: publicPoint,
    rMontgomery: rMontgomery,
    publicMontgomery: publicMontgomery,
  );
}
