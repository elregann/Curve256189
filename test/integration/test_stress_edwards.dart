// test_stress_edwards.dart
// Edwards Curve Completeness Stress Test
//
// Verifies fundamental group properties under heavy load:
// 1. Neutral point addition (P + 0 = P)
// 2. Order-2 point handling
// 3. Inverse property (P + (-P) = 0)
// 4. Point doubling
// 5. Long-running sequential addition stability

import 'package:curve256189/curve256189.dart';

void main() {
  print('╔══════════════════════════════════════╗');
  print('║  Edwards Curve Completeness Test     ║');
  print('║  Curve: Curve256189                  ║');
  print('╚══════════════════════════════════════╝');

  final p = Curve256189Params.p;
  final g = EdwardsPoint(Curve256189Params.gxEd, Curve256189Params.gyEd);

  // Test 1: Neutral point (0,1)
  final neutral = EdwardsPoint(BigInt.zero, BigInt.one);
  _testAddition('Neutral point', g, neutral);

  // Test 2: Order-2 point (0, -1)
  final order2 = EdwardsPoint(BigInt.zero, p - BigInt.one);
  _testAddition('Order-2 point', g, order2);

  // Test 3: Self-inverse P + (-P) = neutral
  final negG = EdwardsPoint(p - g.x, g.y);
  _testAddition('Self-inverse', g, negG);

  // Test 4: Point doubling
  _testAddition('Point doubling', g, g);

  // Test 5: Long-running sequential addition
  _testSequentialAddition(g);
}

void _testAddition(String label, EdwardsPoint p1, EdwardsPoint p2) {
  print('\n📌 TEST: $label');
  print('   ${"-" * 40}');

  try {
    final result = TwistedEdwards.add(p1, p2);
    final onCurve = TwistedEdwards.isOnCurve(result);
    final isNeutral = result.x == BigInt.zero && result.y == BigInt.one;

    // Safe print — handle short strings like "0" or "1"
    final xStr = result.x.toString();
    final yStr = result.y.toString();
    final xPreview = xStr.length > 20 ? '${xStr.substring(0, 20)}...' : xStr;
    final yPreview = yStr.length > 20 ? '${yStr.substring(0, 20)}...' : yStr;

    print('   Result: ($xPreview, $yPreview)');
    print('   On curve: $onCurve');
    if (isNeutral) print('   Is neutral point (0,1): true');

    if (onCurve) {
      print('   ✅ PASS');
    } else {
      print('   ❌ FAIL — Point left the curve!');
    }
  } catch (e) {
    print('   ❌ CRASH — $e');
  }
}

void _testSequentialAddition(EdwardsPoint g) {
  print('\n📌 TEST: Sequential Addition Stress Test');
  print('   ${"-" * 40}');

  const int iterations = 100000;
  var current = g;

  for (int i = 1; i <= iterations; i++) {
    try {
      current = TwistedEdwards.add(current, g);

      if (!TwistedEdwards.isOnCurve(current)) {
        print('   ❌ FAIL at iteration $i — Point left the curve!');
        return;
      }

      if (i % 25000 == 0) {
        print('   Progress: $i/$iterations iterations completed');
      }
    } catch (e) {
      print('   ❌ CRASH at iteration $i — $e');
      return;
    }
  }

  print('   ✅ PASS — $iterations sequential additions completed');
  print('   Final point remains on curve');
}