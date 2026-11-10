/// Elligator 2 point encoding on Curve256189.
///
/// Elligator 2 maps a field element t to a Montgomery x-coordinate. It is a
/// uniform encoding used by protocols that need indistinguishability from
/// random bytes; it is not encryption and it does not hide a message.
///
/// Properties demonstrated here:
///
/// * t and p - t map to the same x-coordinate;
/// * decode() returns a canonical preimage of x (at most (p - 1) / 2), not
///   necessarily the original t;
/// * t = 0 is not encodable;
/// * not every curve point is representable, which is expected.
library;

import 'package:curve256189/curve256189.dart';

void main() {
  print('');
  print('Curve256189 Elligator 2 encoding');
  print('=' * 31);
  print('');

  _step('1. Encode a field element');

  for (final value in [1, 2, 42]) {
    final t = BigInt.from(value);
    final x = Elligator.encode(t);

    if (x == null) {
      print('t = $value is not encodable');
      continue;
    }

    final y = Montgomery.yFromX(x);
    final back = Elligator.decode(x);

    print('t = $value');
    print('  x:          ${_short(x)}');
    print('  on curve:   ${y != null}');
    print('  preimage:   ${back == null ? 'null' : _short(back)}');
    print('  encode(preimage) == x: '
        '${back != null && Elligator.encode(back) == x}');
  }
  print('');
  print('decode() is a right inverse: encode(decode(x)) == x, but');
  print('decode(encode(t)) need not equal t.');
  print('');

  _step('2. Sign symmetry and the t = 0 case');

  final t = BigInt.from(42);
  print('encode(t) == encode(p - t): '
      '${Elligator.encode(t) == Elligator.encode(Elligator.p - t)}');
  print('encode(0): ${Elligator.encode(BigInt.zero)} (not encodable)');
  print('');

  _step('3. Not every point is representable');

  // About half of all curve points have a preimage under encode(). This is a
  // property of Elligator 2, not a bug: callers that need a preimage can
  // retry with a fresh t.
  var representable = 0;
  const samples = 18;
  for (var k = 2; k < 2 + samples; k++) {
    final point = Montgomery.scalarMulFull(BigInt.from(k), MontgomeryPoint.G);
    if (Elligator.decode(point.x) != null) representable++;
  }
  print('$representable of $samples small multiples of G are representable.');
  print('');

  print('Elligator 2 example completed.');
}

void _step(String title) {
  print(title);
  print('-' * title.length);
}

String _short(BigInt value) {
  final hex = value.toRadixString(16);
  return hex.length > 24 ? '${hex.substring(0, 24)}...' : hex;
}
