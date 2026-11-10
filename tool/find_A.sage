# =============================================================================
# Parameter Search - Curve256189
#
# Deterministic scan from A = 0 for the first admissible Montgomery
# coefficient A in
#
#     y^2 = x^3 + A*x^2 + x   over   F_p,   p = 2^256 - 189.
#
# Admissibility (all checks are recomputed for every candidate):
#   * A^2 - 4 is a non-square, so the Montgomery ladder and Elligator 2 are
#     complete / applicable;
#   * #E = 4n and #E_twist = 4nt with n and nt prime (cofactor pair (4, 4));
#   * A - 2 is a square and A + 2 is a non-square, so the dual twisted Edwards
#     model E_(d,a) used by Ed256189 has a complete addition law.
#
# The base point follows the djb / RFC 7748 convention, adapted to cofactor 4:
# take the smallest x >= 1 whose point has order n, and among the two y roots
# choose the even one.
#
# The first hit is A = 61370. The scan stops there, so the runtime is dominated
# by the point counts E.order() for the candidates below it. The script makes
# no uniqueness claim over the full range; it reproduces the first hit only.
# =============================================================================

p = 2**256 - 189
SEARCH_LIMIT = 10**6


def montgomery_rhs(A, x):
    return (x**3 + A * x**2 + x) % p


def even_y_root(A, x):
    """Return the even y with y^2 = rhs(A, x), or None if x is off-curve."""
    rhs = montgomery_rhs(A, x)
    if rhs == 0:
        return 0
    if not Mod(rhs, p).is_square():
        return None
    y = int(Mod(rhs, p).sqrt())
    return y if y % 2 == 0 else p - y


def first_subgroup_point(A, n, E):
    """Smallest x >= 1 whose even-y point has order n."""
    x = 1
    while True:
        y = even_y_root(A, x)
        if y is not None:
            P = E(x, y)
            if n * P == E(0):
                return P
        x += 1


found = False
for A in range(SEARCH_LIMIT + 1):
    # Montgomery ladder / Elligator 2 require A^2 - 4 to be a non-square.
    if Mod(A * A - 4, p).is_square():
        continue

    E = EllipticCurve(GF(p), [0, A, 0, 1, 0])
    order = E.order()

    if order % 4 != 0:
        continue
    n = order // 4
    if not is_prime(n):
        continue

    twist_order = 2 * (p + 1) - order
    if twist_order % 4 != 0:
        continue
    nt = twist_order // 4
    if not is_prime(nt):
        continue

    # Complete dual Edwards model E_(d,a): d = A - 2 square, a = A + 2 non-square.
    if not Mod(A - 2, p).is_square():
        continue
    if Mod(A + 2, p).is_square():
        continue

    G = first_subgroup_point(A, n, E)
    gx, gy = int(G[0]), int(G[1])

    # Dual Edwards base point B = Phi(G): (u, v) = (-x/y, (x+1)/(x-1)).
    Bx = (-gx * inverse_mod(gy, p)) % p
    By = ((gx + 1) * inverse_mod(gx - 1, p)) % p
    B_encoding = By.to_bytes(32, "little").hex() + ("01" if Bx % 2 else "00")

    print("First admissible A =", A)
    print()
    print("p   =", p)
    print("A   =", A)
    print("a24 =", (A + 2) // 4)
    print("n   =", n)
    print("nt  =", nt)
    print("#E  =", order, "= 4 * n")
    print("#Et =", twist_order, "= 4 * nt")
    print()
    print("G (Montgomery, even y) = (")
    print("  ", gx, ",")
    print("  ", gy)
    print(")")
    print("G on curve:", E(gx, gy) == G)
    print("n * G = O :", n * G == E(0))
    print()
    print("B (dual Edwards) = (")
    print("  ", Bx, ",")
    print("  ", By)
    print(")")
    print("B encoding (v little-endian || parity of u):", B_encoding)

    found = True
    break

if not found:
    print("No admissible A found in 0 <= A <=", SEARCH_LIMIT)
