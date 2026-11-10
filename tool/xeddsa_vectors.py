#!/usr/bin/env python3
"""Independent reference implementation and test-vector generator for XEdDSA.

This script intentionally shares no code with the Dart package. It implements
the Curve256189 XEdDSA profile directly from doc/xeddsa.md:

  * curve:            y^2 = x^3 + A*x^2 + x over F_p, p = 2^256 - 189
  * public key:       32-byte little-endian x-coordinate
  * signature:        x(R) (32 bytes) || s (32 bytes little-endian)
  * hash:             SHA-512
  * key derivation:   SHA-512(seed), clamp, mod n, then multiply by 4
  * canonical points: even-y representatives for both P and R
  * nonce:            deterministic, domain-separated, 4-byte counter retry
  * verification:     exact full-point equation [s]G == R + [h]P

The reference is deliberately simple: affine arithmetic, a plain double-and-add
scalar multiplication, and no blinding. It is a correctness oracle, not a
performance implementation.

Run with: python tool/xeddsa_vectors.py
"""

import hashlib
import sys

p = 2**256 - 189
A = 61370
n = 28948022309329048855892746252171976963404671476872247083542990644359122995957
gx = 6
gy = 34517194831513652290546734430452415224722876045332401153182996255764394237320

G = (gx, gy)

DOMAIN = b"Curve256189-XEdDSA-v1"
NONCE_TAG = b"\x01"
CHALLENGE_TAG = b"\x02"

SEED_LENGTH = 32
PUBLIC_KEY_LENGTH = 32
SIGNATURE_LENGTH = 64

# Anchor for the current parameter set (A = 61370). It is regenerated whenever
# the curve parameters change; see the parameter-migration note in README.
ANCHOR_SEED = bytes((1 + i) & 0xFF for i in range(32))
ANCHOR_MESSAGE = b"Hello Curve256189!"
ANCHOR_PUBLIC_KEY = (
    "b1b998018648e7195a06c1b8c6bd029c84d384be33673c010f83a960a1160275"
)
ANCHOR_SIGNATURE = (
    "3f09322f361f003a7e0478f44c3d095a91e6bd5b3e55f5c806d57325a665b5f6"
    "0e0659fb94c480fd0b1daa30d9e32118288a1e53acf2d872a80e53195311fc09"
)


def inv(x):
    return pow(x % p, p - 2, p)


def on_curve(P):
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + A * x * x + x)) % p == 0


def negate(P):
    if P is None:
        return None
    x, y = P
    return (x, (-y) % p)


def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + 2 * A * x1 + 1) * inv(2 * y1) % p
    else:
        slope = (y2 - y1) * inv(x2 - x1) % p

    x3 = (slope * slope - A - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)


def mul(k, P):
    if k < 0:
        return mul(-k, negate(P))
    result = None
    addend = P
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


def point_from_x(x, even_y=True):
    if x <= 0 or x >= p:
        return None

    rhs = (x * x * x + A * x * x + x) % p
    if rhs == 0:
        y = 0
    else:
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p != rhs:
            return None

    if y != 0 and ((y & 1) != (0 if even_y else 1)):
        y = p - y

    return (x, y)


def x_bytes(x):
    return x.to_bytes(32, "little")


def sha512(data):
    return hashlib.sha512(data).digest()


def expand_seed(seed):
    if len(seed) != SEED_LENGTH:
        raise ValueError("seed must be 32 bytes")

    digest = sha512(seed)
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 252   # clear bits 0 and 1 (cofactor 2^2)
    scalar_bytes[31] &= 127  # clear bit 255
    scalar_bytes[31] |= 64   # set bit 254

    sk = int.from_bytes(scalar_bytes, "little") % n
    if sk == 0:
        sk = 1

    a0 = (sk * 4) % n
    return a0, digest[32:]


def canonicalise(scalar, point):
    if point is None:
        raise ValueError("cannot canonicalise the point at infinity")
    if point[1] % 2 == 0:
        return scalar, point

    adjusted = (n - (scalar % n)) % n
    if adjusted == 0:
        raise ValueError("degenerate scalar while canonicalising")
    return adjusted, negate(point)


def key_material(seed):
    a0, prefix = expand_seed(seed)
    canonical = canonicalise(a0, mul(a0, G))
    return canonical[0], canonical[1], prefix


def public_key_from_seed(seed):
    _, P, _ = key_material(seed)
    return x_bytes(P[0])


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


def challenge(x_r, x_p, message):
    digest = sha512(DOMAIN + CHALLENGE_TAG + x_r + x_p + message)
    return int.from_bytes(digest, "little") % n


def sign(seed, message):
    a, P, prefix = key_material(seed)

    r0 = derive_nonce(prefix, message)
    r, R = canonicalise(r0, mul(r0, G))

    x_r = x_bytes(R[0])
    x_p = x_bytes(P[0])
    h = challenge(x_r, x_p, message)
    s = (r + h * a) % n

    return x_r + s.to_bytes(32, "little")


def verify(message, signature, public_key):
    if len(signature) != SIGNATURE_LENGTH:
        return False
    if len(public_key) != PUBLIC_KEY_LENGTH:
        return False

    x_r = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= n:
        return False

    R = point_from_x(int.from_bytes(x_r, "little"), even_y=True)
    if R is None:
        return False
    if mul(n, R) is not None:
        return False

    P = point_from_x(int.from_bytes(public_key, "little"), even_y=True)
    if P is None:
        return False
    if mul(n, P) is not None:
        return False

    h = challenge(x_r, public_key, message)
    return mul(s, G) == add(R, mul(h, P))


def seed_from(start):
    return bytes((start + i) & 0xFF for i in range(32))


def vector_material():
    seeds = [
        ("seed0", seed_from(0)),
        ("seed1", seed_from(1)),
        ("seed7", seed_from(7)),
        (
            "ed25519",
            bytes.fromhex(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
            ),
        ),
    ]
    messages = [
        ("empty", b""),
        ("abc", b"abc"),
        ("hello", b"Hello Curve256189!"),
        ("1000", bytes((i * 7 + 3) & 0xFF for i in range(1000))),
    ]

    vectors = []
    for seed_name, seed in seeds:
        public_key = public_key_from_seed(seed)
        for message_name, message in messages:
            signature = sign(seed, message)
            assert public_key_from_seed(seed) == public_key
            assert verify(message, signature, public_key)
            vectors.append(
                {
                    "name": "%s/%s" % (seed_name, message_name),
                    "seed": seed.hex(),
                    "publicKey": public_key.hex(),
                    "message": message.hex(),
                    "signature": signature.hex(),
                }
            )
    return seeds, vectors


def write_dart(path, seeds, vectors):
    lines = [
        "// Generated by tool/xeddsa_vectors.py. Do not edit by hand.",
        "//",
        "// Montgomery curve y^2 = x^3 + A x^2 + x",
        "//   p = 2^256 - 189, A = %d" % A,
        "//   n = %d" % n,
        "// Encoding: x (32 bytes little-endian).",
        "// Signature: x(R) (32 bytes) || s (32 bytes little-endian).",
        "",
        "const List<Map<String, String>> xeddsaVectors = [",
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
    assert on_curve(G), "base point is not on the Montgomery curve"
    assert mul(n, G) is None, "base point does not have order n"
    assert point_from_x(gx, even_y=True) == G

    assert public_key_from_seed(ANCHOR_SEED).hex() == ANCHOR_PUBLIC_KEY
    assert sign(ANCHOR_SEED, ANCHOR_MESSAGE).hex() == ANCHOR_SIGNATURE

    seeds, vectors = vector_material()

    if len(sys.argv) > 1 and sys.argv[1] == "--dart":
        path = sys.argv[2] if len(sys.argv) > 2 else "test/xeddsa_vectors.dart"
        write_dart(path, seeds, vectors)
        print("wrote %s (%d vectors)" % (path, len(vectors)))
        return

    print("// Generated by tool/xeddsa_vectors.py. Do not edit by hand.")
    print("// A = %d, n = %d" % (A, n))
    print()
    for name, seed in seeds:
        print("%s seed   %s" % (name, seed.hex()))
        print("%s pk     %s" % (name, public_key_from_seed(seed).hex()))
    print()
    for vector in vectors:
        print("%s" % vector["name"])
        if len(vector["message"]) <= 128:
            print("  message %s" % vector["message"])
        print("  pk      %s" % vector["publicKey"])
        print("  sig     %s" % vector["signature"])

    print()
    print("base point")
    print("  x %s" % gx.to_bytes(32, "little").hex())
    print("  y %s" % gy.to_bytes(32, "little").hex())


if __name__ == "__main__":
    main()
