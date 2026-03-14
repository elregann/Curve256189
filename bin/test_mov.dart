import 'src/params.dart';

void main() {

  final p = Curve256189Params.p;
  final n = Curve256189Params.n;

  print("================================");
  print(" Curve256189 MOV Attack Test");
  print("================================");

  const maxK = 50;

  BigInt pk = p % n;

  for (int k = 1; k <= maxK; k++) {

    if ((pk - BigInt.one) % n == BigInt.zero) {
      print("⚠️ MOV vulnerability detected at k = $k");
      return;
    }

    print("k = $k checked");

    pk = (pk * p) % n;
  }

  print("✅ No MOV attack vulnerability for k <= $maxK");

  print("================================");
}