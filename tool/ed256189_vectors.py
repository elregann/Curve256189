#!/usr/bin/env python3
"""Independent reference implementation and test-vector generator for Ed256189.

This script intentionally shares no code with the Dart package. It implements
Ed256189 directly from doc/ed256189.md:

  * signature curve: the complete twisted Edwards model E_{d,a}
  * field:            p = 2^256 - 189
  * encoding:         v || parity(u), 33 bytes
  * hash:             SHA-512
  * scalar pruning:   clear bits 0 and 1, clear bit 255, set bit 254
  * signature:        R (33 bytes) || S (32 bytes little-endian)

Run with: python tool/ed256189_vectors.py
"""

import hashlib
import sys

p = 2**256 - 189
A = 479597
a_natural = A + 2  # 479599, quadratic non-residue
d_natural = A - 2  # 479595, quadratic residue

# Signature curve E_{d,a}: a' = d_natural (square), d' = a_natural (non-square).
a = d_natural
d = a_natural

n = 28948022309329048855892746252171976963257918617752773869725216245594308445583
gx = 107794463287790729181798923754704247240057009056848862892287801730172665808003
gy = 5935226473593038842940459288042955305454636525326183552707973708623513097342

DOMAIN = b"Curve256189-Ed256189-v1"
NONCE_TAG = b"\x01"
CHALLENGE_TAG = b"\x02"

SEED_LENGTH = 32
PUBLIC_KEY_LENGTH = 33
SIGNATURE_LENGTH = 65


def inv(x):
    return pow(x % p, p - 2, p)


def on_curve(P):
    x, y = P
    x2 = x * x % p
    y2 = y * y % p
    return (a * x2 + y2 - 1 - d * x2 * y2) % p == 0


def add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    t = d * x1 * x2 * y1 * y2 % p
    x3 = (x1 * y2 + y1 * x2) * inv(1 + t) % p
    y3 = (y1 * y2 - a * x1 * x2) * inv(1 - t) % p
    return (x3, y3)


def negate(P):
    x, y = P
    return ((-x) % p, y)


def mul(k, P):
    k %= n
    R = (0, 1)
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R


def encode(P):
    x, y = P
    return y.to_bytes(32, "little") + bytes([x & 1])


def decode(raw):
    if len(raw) != PUBLIC_KEY_LENGTH:
        return None
    sign = raw[32]
    if sign > 1:
        return None
    v = int.from_bytes(raw[:32], "little")
    if v >= p:
        return None
    v2 = v * v % p
    denominator = (a - d * v2) % p
    if denominator == 0:
        return None
    u2 = (1 - v2) * inv(denominator) % p
    u = pow(u2, (p + 1) // 4, p)
    if u * u % p != u2:
        return None
    if u == 0:
        if sign == 1:
            return None
    elif (u & 1) != sign:
        u = p - u
    P = (u, v)
    return P if on_curve(P) else None


def sha512(data):
    return hashlib.sha512(data).digest()


def expand_seed(seed):
    if len(seed) != SEED_LENGTH:
        raise ValueError("seed must be 32 bytes")
    digest = sha512(seed)
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 0xFC  # clear bits 0 and 1 (cofactor 2^2)
    scalar_bytes[31] &= 0x7F  # clear bit 255
    scalar_bytes[31] |= 0x40  # set bit 254
    scalar = int.from_bytes(scalar_bytes, "little")
    return scalar, digest[32:]


def base_point():
    # Phi(x, y) = (-x, 1/y) applied to the natural Edwards generator.
    u = (-gx * inv(gy)) % p
    v = (gx + 1) * inv(gx - 1) % p
    return (u, v)


def derive_nonce(prefix, message):
    counter = 0
    while True:
        digest = sha512(
            DOMAIN
            + NONCE_TAG
            + prefix
            + counter.to_bytes(4, "little")
            + message
        )
        r = int.from_bytes(digest, "little") % n
        if r != 0:
            return r
        counter += 1


def challenge(r_encoded, public_key, message):
    digest = sha512(DOMAIN + CHALLENGE_TAG + r_encoded + public_key + message)
    return int.from_bytes(digest, "little") % n


def keypair(seed):
    scalar, _ = expand_seed(seed)
    return encode(mul(scalar, base_point()))


def sign(seed, message):
    scalar, prefix = expand_seed(seed)
    public_key = encode(mul(scalar, base_point()))
    r = derive_nonce(prefix, message)
    r_encoded = encode(mul(r, base_point()))
    k = challenge(r_encoded, public_key, message)
    s = (r + k * scalar) % n
    return public_key, r_encoded + s.to_bytes(32, "little")


def verify(public_key, message, signature):
    if len(public_key) != PUBLIC_KEY_LENGTH:
        return False
    if len(signature) != SIGNATURE_LENGTH:
        return False
    r_encoded = signature[:PUBLIC_KEY_LENGTH]
    s = int.from_bytes(signature[PUBLIC_KEY_LENGTH:], "little")
    if s >= n:
        return False
    A = decode(public_key)
    R = decode(r_encoded)
    if A is None or R is None:
        return False
    k = challenge(r_encoded, public_key, message)
    return mul(s, base_point()) == add(R, mul(k, A))


def seed_from(start):
    return bytes((start + i) & 0xFF for i in range(32))


def hex32(value):
    return value.to_bytes(32, "little").hex()


def vector_material():
    seeds = [
        ("seed0", seed_from(0)),
        ("seed1", seed_from(1)),
        ("seed7", seed_from(7)),
        ("ed25519", bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )),
    ]
    messages = [
        ("empty", b""),
        ("abc", b"abc"),
        ("curve", b"Curve256189 Ed256189"),
        ("1000", bytes((i * 7 + 3) & 0xFF for i in range(1000))),
    ]

    vectors = []
    for seed_name, seed in seeds:
        public_key = keypair(seed)
        for message_name, message in messages:
            pk, sig = sign(seed, message)
            assert pk == public_key
            assert verify(pk, message, sig)
            vectors.append({
                "name": "%s/%s" % (seed_name, message_name),
                "seed": seed.hex(),
                "publicKey": pk.hex(),
                "message": message.hex(),
                "signature": sig.hex(),
            })
    return seeds, vectors


def write_dart(path, seeds, vectors):
    lines = [
        "// Generated by tool/ed256189_vectors.py. Do not edit by hand.",
        "//",
        "// Signature curve E_{d,a}: d u^2 + v^2 = 1 + a u^2 v^2",
        "//   a = %d (square), d = %d (non-square)" % (a, d),
        "//   n = %d" % n,
        "// Encoding: v (32 bytes little-endian) || parity(u) (1 byte).",
        "// Signature: R (33 bytes) || S (32 bytes little-endian).",
        "",
        "const List<Map<String, String>> ed256189Vectors = [",
    ]
    for vector in vectors:
        lines.append("  {")
        for key in ("name", "seed", "publicKey", "message", "signature"):
            line = "    '%s': '%s'," % (key, vector[key])
            if len(line) <= 80:
                lines.append(line)
            else:
                lines.append("    '%s':" % key)
                lines.append("        '%s'," % vector[key])
        lines.append("  },")
    lines.append("];")
    lines.append("")

    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))


def main():
    B = base_point()
    assert on_curve(B), "dual generator is not on E_{d,a}"
    assert mul(n, B) == (0, 1), "dual generator does not have order n"
    assert decode(encode(B)) == B

    seeds, vectors = vector_material()

    if len(sys.argv) > 1 and sys.argv[1] == "--dart":
        path = sys.argv[2] if len(sys.argv) > 2 else "test/ed256189_vectors.dart"
        write_dart(path, seeds, vectors)
        print("wrote %s (%d vectors)" % (path, len(vectors)))
        return

    print("// Generated by tool/ed256189_vectors.py. Do not edit by hand.")
    print("// a = %d (square), d = %d (non-square), n = %d" % (a, d, n))
    print()
    for name, seed in seeds:
        print("%s seed   %s" % (name, seed.hex()))
        print("%s pk     %s" % (name, keypair(seed).hex()))
    print()
    for vector in vectors:
        print("%s" % vector["name"])
        if len(vector["message"]) <= 128:
            print("  message %s" % vector["message"])
        print("  pk      %s" % vector["publicKey"])
        print("  sig     %s" % vector["signature"])

    print()
    print("base point")
    print("  u %s" % hex32(B[0]))
    print("  v %s" % hex32(B[1]))
    print("  enc %s" % encode(B).hex())


if __name__ == "__main__":
    main()
