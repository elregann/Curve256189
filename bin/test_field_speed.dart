import 'dart:math';
import 'src/field.dart';
import 'src/montgomery.dart';
import 'src/params.dart';

void main() {

  final rand = Random();

  BigInt rand256() {
    BigInt r = BigInt.zero;
    for (int i = 0; i < 8; i++) {
      r = (r << 32) | BigInt.from(rand.nextInt(1 << 32));
    }
    return r % Curve256189Params.p;
  }

  print("================================");
  print(" Curve256189 Benchmark");
  print("================================");

  // FIELD TEST
  final a = rand256();
  final b = rand256();

  const fieldIterations = 100000;

  final swField = Stopwatch()..start();

  BigInt r = BigInt.zero;

  for (int i = 0; i < fieldIterations; i++) {
    r = FieldElement.mul(a, b);
  }

  swField.stop();

  print("Result sample: $r");
  print("Field time: ${swField.elapsedMilliseconds} ms");

  // SCALAR TEST

  BigInt randomScalar() => rand256() % Curve256189Params.n;

  const scalarIterations = 1000;

  final swScalar = Stopwatch()..start();

  for (int i = 0; i < scalarIterations; i++) {

    final k = randomScalar();

    Montgomery.scalarMul(
      k,
      MontgomeryPoint.G,
    );

  }

  swScalar.stop();

  print("Scalar time: ${swScalar.elapsedMilliseconds} ms");
}