// params.dart

// Curve256189 Parameters
// Montgomery: y² = x³ + Ax² + x
// Twisted Edwards: ax² + y² = 1 + dx²y²
class Curve256189Params {
  // Prime field modulus: 2^256 - 189
  static final BigInt p = BigInt.parse(
      '115792089237316195423570985008687907853269984665640564039457584007913129639747'
  );

  // Montgomery curve coefficient A
  static final BigInt A = BigInt.from(479597);

  // Precomputed Montgomery constant: (A + 2) / 4 mod p
  static final BigInt a24 = BigInt.parse(
      '45183421064825764087240000763972131628468230599262747728931217572732213985918'
  );

  // Twisted Edwards coefficient: a = A + 2
  static final BigInt aEd = A + BigInt.two;

  // Twisted Edwards coefficient d
  static final BigInt d = BigInt.parse(
      '37923678341782778346812307868082839651375912191935673838064381839050879487433'
  );

  // Curve cofactor h
  static final int h = 4;

  // Prime order n of the main subgroup
  static final BigInt n = BigInt.parse(
      '28948022309329048855892746252171976963257918617752773869725216245594308445583'
  );

  // Montgomery base point x-coordinate
  static final BigInt gx = BigInt.parse(
      '107794463287790729181798923754704247240057009056848862892287801730172665808003'
  );

  // Montgomery base point y-coordinate
  static final BigInt gy = BigInt.parse(
      '5935226473593038842940459288042955305454636525326183552707973708623513097342'
  );

  // Twisted Edwards base point x-coordinate
  static final BigInt gxEd = BigInt.parse(
      '62454605460742073543342701757224786493190389702282842860057684960145974238215'
  );

  // Twisted Edwards base point y-coordinate
  static final BigInt gyEd = BigInt.parse(
      '50344289031653621710904814998481842241301136639183813561465471305870279522904'
  );
}