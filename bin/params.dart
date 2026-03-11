// Curve256189 Parameters
// Montgomery curve: By² = x³ + Ax² + x
// Prime: 2^256 - 189

class Curve256189Params {
  // Prime field
  static final BigInt p = BigInt.parse(
      '115792089237316195423570985008687907853269984665640564039457584007913129639747'
  );

  // Montgomery coefficient
  static final BigInt A = BigInt.from(479597);

  // Cofactor
  static final int h = 4;

  // Subgroup order (prime)
  static final BigInt n = BigInt.parse(
      '28948022309329048855892746252171976963257918617752773869725216245594308445583'
  );

  // Base Point
  static final BigInt gx = BigInt.parse(
      '107794463287790729181798923754704247240057009056848862892287801730172665808003'
  );

  static final BigInt gy = BigInt.parse(
      '5935226473593038842940459288042955305454636525326183552707973708623513097342'
  );

  // Base Point (Twisted Edwards)
  static final BigInt gxEd = BigInt.parse(
      '62454605460742073543342701757224786493190389702282842860057684960145974238215'
  );

  static final BigInt gyEd = BigInt.parse(
      '50344289031653621710904814998481842241301136639183813561465471305870279522904'
  );
}