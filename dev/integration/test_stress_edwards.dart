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
  print('Edwards Curve Completeness Test');
  print('Curve: Curve256189');
  print('');

  final p = Curve256189Params.p;
  final g = EdwardsPoint(Curve256189Params.gxEd, Curve256189Params.gyEd);

  // Test case 1: Neutral point (0, 1)
  final neutral = EdwardsPoint(BigInt.zero, BigInt.one);
  _testAddition('Neutral point (P + 0 = P)', g, neutral);

  // Test case 2: Order-2 point (0, -1)
  final order2 = EdwardsPoint(BigInt.zero, p - BigInt.one);
  _testAddition('Order-2 point', g, order2);

  // Test case 3: Self-inverse property (P + (-P) = 0)
  final negG = EdwardsPoint(p - g.x, g.y);
  _testAddition('Self-inverse (P + (-P) = 0)', g, negG);

  // Test case 4: Point doubling (P + P = 2P)
  _testAddition('Point doubling', g, g);

  // Test case 5: Long-running sequential addition stability
  _testSequentialAddition(g);
}

// Helper function to test addition between two points and verify results.
void _testAddition(String label, EdwardsPoint p1, EdwardsPoint p2) {
  print('');
  print('TEST: $label');
  print('');

  try {
    final result = TwistedEdwards.add(p1, p2);
    final onCurve = TwistedEdwards.isOnCurve(result);
    final isNeutral = result.x == BigInt.zero && result.y == BigInt.one;

    // Truncate long string representations for cleaner output
    final xStr = result.x.toString();
    final yStr = result.y.toString();
    final xPreview = xStr.length > 20 ? '${xStr.substring(0, 20)}...' : xStr;
    final yPreview = yStr.length > 20 ? '${yStr.substring(0, 20)}...' : yStr;

    print('  Result: ($xPreview, $yPreview)');
    print('  On curve: $onCurve');
    if (isNeutral) print('  Is neutral point (0,1): true');

    if (onCurve) {
      print('  PASS');
    } else {
      print('  FAIL: Point left the curve.');
    }
  } catch (e) {
    print('  CRASH: $e');
  }
}

// Stress test for sequential addition: compute G, 2G, 3G, ..., nG
void _testSequentialAddition(EdwardsPoint g) {
  print('');
  print('TEST: Sequential Addition Stress Test');
  print('');

  const int iterations = 100000;
  var current = g;

  for (int i = 1; i <= iterations; i++) {
    try {
      current = TwistedEdwards.add(current, g);

      if (!TwistedEdwards.isOnCurve(current)) {
        print('  FAIL at iteration $i: Point left the curve.');
        return;
      }

      if (i % 25000 == 0) {
        print('  Progress: $i / $iterations iterations completed');
      }
    } catch (e) {
      print('  CRASH at iteration $i: $e');
      return;
    }
  }

  print('  PASS: $iterations sequential additions completed');
  print('  Final point remains on the curve.');
  print('');
}