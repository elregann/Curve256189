import 'src/params.dart';

void main() {

  final p = Curve256189Params.p;
  final n = Curve256189Params.n;

  print("================================");
  print(" Curve256189 Twist Security Test");
  print("================================");

  // trace Frobenius
  final t = p + BigInt.one - n;

  print("trace t = $t");

  // twist order
  final twist = p + BigInt.one + t;

  print("Twist order = $twist");

  // cek faktor kecil
  final smallPrimes = [
    2,3,5,7,11,13,17,19,23,29,
    31,37,41,43,47,53,59,61
  ];

  bool weak = false;

  for (final prime in smallPrimes) {

    final d = BigInt.from(prime);

    if (twist % d == BigInt.zero) {
      print("⚠️ twist divisible by $prime");
      weak = true;
    }

  }

  if (!weak) {
    print("✅ No small subgroup factors detected");
  }

  print("================================");
}