// params.dart

// Curve256189 Parameters
// Montgomery: y² = x³ + Ax² + x
// Twisted Edwards: ax² + y² = 1 + dx²y²
class Curve256189Params {
  // Prime field modulus: 2^256 - 189
  static final BigInt p = BigInt.parse(
      '115792089237316195423570985008687907853269984665640564039457584007913129639747');

  // Montgomery curve coefficient A
  static final BigInt A = BigInt.from(61370);

  // Precomputed Montgomery constant: (A + 2) / 4 mod p
  static final BigInt a24 = BigInt.from(15343);

  // Twisted Edwards coefficient: a = A + 2
  static final BigInt aEd = A + BigInt.two;

  // Twisted Edwards coefficient d
  static final BigInt d = BigInt.from(61368);

  // Curve cofactor h
  static final int h = 4;

  // Prime order n of the main subgroup
  static final BigInt n = BigInt.parse(
      '28948022309329048855892746252171976963404671476872247083542990644359122995957');

  // Montgomery base point x-coordinate
  static final BigInt gx = BigInt.from(6);

  // Montgomery base point y-coordinate
  static final BigInt gy = BigInt.parse(
      '34517194831513652290546734430452415224722876045332401153182996255764394237320');

  // Twisted Edwards base point x-coordinate
  static final BigInt gxEd = BigInt.parse(
      '42295082034244311968184368205419199943447855438513562220070960560338748913112');

  // Twisted Edwards base point y-coordinate
  static final BigInt gyEd = BigInt.parse(
      '16541727033902313631938712144098272550467140666520080577065369143987589948536');
}
