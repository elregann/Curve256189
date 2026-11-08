// xeddsa_internal.dart

// Shared parsing and validation for XEdDSA signatures.
//
// This file is intentionally not exported from lib/curve256189.dart. It exists
// so that individual verification and batch verification cannot drift apart:
// both must accept exactly the same set of encoded inputs.

import 'dart:typed_data';

import 'montgomery.dart';
import 'params.dart';

const int xeddsaPublicKeyLength = 32;
const int xeddsaSignatureLength = 64;

// A signature/public-key pair that has passed every structural check:
//   * exact lengths,
//   * canonical s < n,
//   * canonical even-y x-coordinate for R,
//   * canonical even-y x-coordinate for P,
//   * non-identity prime-order subgroup membership for R and P.
class XEdDSAVerifiedInput {
  final Uint8List xR;
  final BigInt s;
  final MontgomeryPoint R;
  final MontgomeryPoint P;

  XEdDSAVerifiedInput({
    required this.xR,
    required this.s,
    required this.R,
    required this.P,
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
XEdDSAVerifiedInput? parseXEdDSAInput(
  Uint8List signature,
  Uint8List publicKey,
) {
  if (signature.length != xeddsaSignatureLength) return null;
  if (publicKey.length != xeddsaPublicKeyLength) return null;

  final xR = Uint8List.fromList(signature.sublist(0, 32));
  final s = _decodeLittleEndian(Uint8List.fromList(signature.sublist(32, 64)));

  // s must be canonical.
  if (s >= Curve256189Params.n) return null;

  // Decode R and P as canonical even-y points.
  final R = Montgomery.pointFromX(
    _decodeLittleEndian(xR),
    evenY: true,
  );
  if (R == null) return null;
  if (!Montgomery.isInPrimeOrderSubgroup(R)) return null;

  final P = Montgomery.pointFromX(
    _decodeLittleEndian(publicKey),
    evenY: true,
  );
  if (P == null) return null;
  if (!Montgomery.isInPrimeOrderSubgroup(P)) return null;

  return XEdDSAVerifiedInput(xR: xR, s: s, R: R, P: P);
}
