// Curve256189 Parameters
// Montgomery curve: y² = x³ + Ax² + x (B=1)
// Twisted Edwards: ax² + y² = 1 + dx²y² (dimana a = A+2)
// Prime: 2^256 - 189

class Curve256189Params {
  // 1. Prime field (2^256 - 189)
  static final BigInt p = BigInt.parse(
      '115792089237316195423570985008687907853269984665640564039457584007913129639747'
  );

  // 2. Montgomery coefficient
  static final BigInt A = BigInt.from(479597);

  // 3. Montgomery constant a24: (A + 2) / 4 mod p
  // Digunakan untuk optimasi Montgomery Ladder
  static final BigInt a24 = BigInt.parse(
      '45183421064825764087240000763972131628468230599262747728931217572732213985918'
  );

  // 4. Twisted Edwards coefficients
  // a = A + 2
  static final BigInt aEd = A + BigInt.two;
  // d (Twisted Edwards coefficient)
  static final BigInt d = BigInt.parse(
      '37923678341782778346812307868082839651375912191935673838064381839050879487433'
  );

  // 5. Curve Order & Cofactor
  // h = 4 (Kofaktor)
  static final int h = 4;
  // n = Subgroup order (Prime order of the base point)
  static final BigInt n = BigInt.parse(
      '28948022309329048855892746252171976963257918617752773869725216245594308445583'
  );

  // 6. Base Point G (Montgomery)
  static final BigInt gx = BigInt.parse(
      '107794463287790729181798923754704247240057009056848862892287801730172665808003'
  );
  static final BigInt gy = BigInt.parse(
      '5935226473593038842940459288042955305454636525326183552707973708623513097342'
  );

  // 7. Base Point G (Twisted Edwards)
  static final BigInt gxEd = BigInt.parse(
      '62454605460742073543342701757224786493190389702282842860057684960145974238215'
  );
  static final BigInt gyEd = BigInt.parse(
      '50344289031653621710904814998481842241301136639183813561465471305870279522904'
  );
}