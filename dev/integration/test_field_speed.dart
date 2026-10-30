// test_field_speed.dart

// Curve256189 Performance Benchmark
// Measures: field operations, scalar multiplication, point operations
//
// Each benchmark runs multiple iterations with a warm-up phase
// to ensure accurate Just-In-Time compilation measurements.

import 'dart:math';
import 'package:curve256189/curve256189.dart';

void main() {
  print('Curve256189 Performance Benchmark');
  print('');

  final random = Random.secure();

  BigInt randomField() {
    BigInt r = BigInt.zero;
    for (int i = 0; i < 8; i++) {
      r = (r << 32) | BigInt.from(random.nextInt(1 << 32));
    }
    return r % Curve256189Params.p;
  }

  BigInt randomScalar() {
    BigInt r = BigInt.zero;
    for (int i = 0; i < 8; i++) {
      r = (r << 32) | BigInt.from(random.nextInt(1 << 32));
    }
    return r % Curve256189Params.n;
  }

  // Section 1: Field Multiplication Benchmark (GF(p))
  print('Field Multiplication (GF(p))');
  print('');

  const fieldIterations = 100000;
  const fieldWarmup = 10000;

  // Warm-up phase to stabilize JIT compilation
  final a = randomField();
  final b = randomField();
  for (int i = 0; i < fieldWarmup; i++) {
    FieldElement.mul(a, b);
  }

  // Measurement phase
  final stopwatchField = Stopwatch()..start();
  BigInt fieldResult = BigInt.zero;
  for (int i = 0; i < fieldIterations; i++) {
    fieldResult = FieldElement.mul(a, b);
  }
  stopwatchField.stop();

  final fieldTime = stopwatchField.elapsedMicroseconds / fieldIterations;
  print('Iterations: $fieldIterations');
  print('Total time: ${stopwatchField.elapsedMilliseconds} ms');
  print('Average time: ${fieldTime.toStringAsFixed(2)} microseconds per operation');
  print('Sample: ${fieldResult.toString().substring(0, 20)}...');
  print('');

  // Section 2: Scalar Multiplication Benchmark (Montgomery Ladder)
  print('Scalar Multiplication (Montgomery Ladder)');
  print('');

  const scalarIterations = 1000;
  const scalarWarmup = 100;

  // Warm-up phase
  final basePoint = MontgomeryPoint.G;
  for (int i = 0; i < scalarWarmup; i++) {
    final k = randomScalar();
    Montgomery.scalarMul(k, basePoint);
  }

  // Measurement phase
  final stopwatchScalar = Stopwatch()..start();
  MontgomeryPoint scalarResult = MontgomeryPoint.infinity();
  for (int i = 0; i < scalarIterations; i++) {
    final k = randomScalar();
    scalarResult = Montgomery.scalarMul(k, basePoint);
  }
  stopwatchScalar.stop();

  final scalarTime = stopwatchScalar.elapsedMicroseconds / scalarIterations;
  print('Iterations: $scalarIterations');
  print('Total time: ${stopwatchScalar.elapsedMilliseconds} ms');
  print('Average time: ${scalarTime.toStringAsFixed(2)} microseconds per operation');
  print('Sample: x = ${scalarResult.x.toString().substring(0, 20)}...');
  print('');

  // Section 3: Point Addition Benchmark (Twisted Edwards)
  print('Point Addition (Twisted Edwards)');
  print('');

  const addIterations = 100000;
  const addWarmup = 10000;

  // Generate two random points for benchmarking
  final scalar1 = randomScalar();
  final scalar2 = randomScalar();
  final point1 = TwistedEdwards.scalarMul(scalar1, EdDSA.G);
  final point2 = TwistedEdwards.scalarMul(scalar2, EdDSA.G);

  // Warm-up phase
  for (int i = 0; i < addWarmup; i++) {
    TwistedEdwards.add(point1, point2);
  }

  // Measurement phase
  final stopwatchAdd = Stopwatch()..start();
  EdwardsPoint addResult = point1;  // Initialize with a valid point
  for (int i = 0; i < addIterations; i++) {
    addResult = TwistedEdwards.add(point1, point2);
  }
  stopwatchAdd.stop();

  final addTime = stopwatchAdd.elapsedMicroseconds / addIterations;
  print('Iterations: $addIterations');
  print('Total time: ${stopwatchAdd.elapsedMilliseconds} ms');
  print('Average time: ${addTime.toStringAsFixed(2)} microseconds per operation');
  print('Sample: (${addResult.x.toString().substring(0, 10)}..., ${addResult.y.toString().substring(0, 10)}...)');
  print('');

  // Section 4: Benchmark Summary
  print('BENCHMARK SUMMARY');
  print('Field multiplication: ${fieldTime.toStringAsFixed(2)} microseconds per operation');
  print('Scalar multiplication: ${scalarTime.toStringAsFixed(2)} microseconds per operation');
  print('Point addition: ${addTime.toStringAsFixed(2)} microseconds per operation');
}