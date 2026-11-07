// Shared helpers for the test suite.

import 'dart:typed_data';

String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List fromHex(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

/// 32-byte little-endian encoding of a non-negative integer below 2^256.
Uint8List encodeLE32(BigInt value) {
  final out = Uint8List(32);
  var v = value;
  for (var i = 0; i < 32; i++) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return out;
}

Uint8List bytesOf(String s) => Uint8List.fromList(s.codeUnits);

/// Deterministic seed: bytes start, start+1, ... (mod 256).
Uint8List seedFrom(int start) =>
    Uint8List.fromList(List.generate(32, (i) => (start + i) & 0xff));

BigInt big(String decimal) => BigInt.parse(decimal);
