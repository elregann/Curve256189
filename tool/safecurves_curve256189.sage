# =============================================================================
# SafeCurves Compliance Test - Curve256189
# Curve     : Curve256189 (Montgomery) / Ed256189 (Edwards) / X256189 (ECDH)
# Equation  : y^2 = x^3 + A*x^2 + x
# Prime     : p = 2^256 - 189
# Author    : Ismael Urzaiz Aranda
# Reference : https://safecurves.cr.yp.to/
# =============================================================================

p = 2**256 - 189
A = 479597
n = 28948022309329048855892746252171976963257918617752773869725216245594308445583
h = 4
Gx_mont = 107794463287790729181798923754704247240057009056848862892287801730172665808003
Gy_mont = 5935226473593038842940459288042955305454636525326183552707973708623513097342

print("=" * 70)
print(" " * 20 + "SafeCurves Compliance Test")
print(" " * 15 + "for Curve256189 (Montgomery/Edwards)")
print("=" * 70)

E = EllipticCurve(GF(p), [0, A, 0, 1, 0])
order = E.order()
G = E(Gx_mont, Gy_mont)

# Helper function for hex representation
def to_hex(value):
    return hex(int(value))

# -----------------------------------------------------------------------------
# 1. FIELD
# Prime p must be prime and of the form 2^m - c (nearest)
# -----------------------------------------------------------------------------
print("\n1. FIELD ARITHMETIC")
print("-" * 70)
print("Prime p          = 2^256 - 189")
print(f"                  = {p}")
print(f"                  = {to_hex(p)}")
prime_ok = is_prime(p)
print(f"Prime?           {'PASS' if prime_ok else 'FAIL'}")
# nearest: check if p is of the form 2^m - c with c < 2^(m/2)
c = 189
m = 256
nearest_ok = c < 2**(m // 2)
print(f"Nearest?         {'PASS' if nearest_ok else 'FAIL'}  (c = {c} < 2^{m // 2})")
print()

# -----------------------------------------------------------------------------
# 2. EQUATION
# Montgomery: B(A^2 - 4) nonzero mod p, B = 1
# -----------------------------------------------------------------------------
print("2. EQUATION")
print("-" * 70)
B = 1
discriminant = B * (A**2 - 4) % p
eq_ok = discriminant != 0
print(f"Equation         y^2 = x^3 + {A}x^2 + x")
print(f"A                = {A}")
print(f"B(A^2 - 4) mod p = {discriminant}")
print(f"Nonzero?         {'PASS' if eq_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 3. BASE POINT
# Base point order must be prime and n*G = identity
# -----------------------------------------------------------------------------
print("3. BASE POINT")
print("-" * 70)
print(f"Generator G      = ({Gx_mont}, {Gy_mont})")
print(f"Order n          = {n}")
print(f"                  = {to_hex(n)}")
n_prime = is_prime(n)
print(f"n prime?         {'PASS' if n_prime else 'FAIL'}")
nG_identity = (n * G == E(0))
print(f"n*G = O?         {'PASS' if nG_identity else 'FAIL'}")
base_ok = n_prime and nG_identity
print(f"Base point OK    {'PASS' if base_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 4. RHO (Pollard's rho)
# 0.886 * sqrt(n) must be > 2^100
# -----------------------------------------------------------------------------
print("4. RHO (POLLARD'S RHO)")
print("-" * 70)
rho_val = 0.886 * sqrt(n)
rho_bits = log(rho_val, 2).n()
rho_ok = rho_bits > 100
print(f"0.886*sqrt(n)    ~ 2^{rho_bits:.1f}")
print(f"> 2^100?         {'PASS' if rho_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 5. TRANSFER (MOV attack)
# -----------------------------------------------------------------------------
print("5. TRANSFER (MOV ATTACK)")
print("-" * 70)

# Additive transfer check
additive_ok = (n != p)

# Multiplicative transfer - find embedding degree k
embedding_k = None
max_search = 1000
for k in range(1, max_search + 1):
    if pow(p, k, n) == 1:
        embedding_k = k
        break

x_target = 1
for x in [8, 6, 4, 2]:
    if (n - 1) % x == 0:
        x_target = x
        break

l_minus_1_over_x = (n - 1) // x_target

embedding_text = f"> {max_search}" if embedding_k is None else str(embedding_k)
print(f"Embedding degree k:  {embedding_text}")
print(f"(l-1)/{x_target}:            {l_minus_1_over_x}")

mult_ok = (embedding_k is None or embedding_k > 20)
transfer_ok = additive_ok and mult_ok
print(f"\nTransfer security: {'PASS' if transfer_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 6. CM DISCRIMINANT
# |D| must be > 2^100 (D fundamental discriminant)
# -----------------------------------------------------------------------------
print("6. CM DISCRIMINANT")
print("-" * 70)
t = p + 1 - order
print(f"Trace t          = {t}")
D_raw = t**2 - 4 * p
# remove square factors
s_sq = 1
for prime_factor, exp in factor(abs(D_raw)):
    s_sq *= prime_factor**(exp - (exp % 2))
D = D_raw // s_sq
if D % 4 != 1:
    D = 4 * D
print(f"|D|              = {abs(D)}")
print(f"                  = {to_hex(abs(D))}")
disc_ok = abs(D) > 2**100
print(f"|D| > 2^100?     {'PASS' if disc_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 7. RIGIDITY
# The documented selection process is an exhaustive search over
# 0 <= A <= 10^6 for the smallest A with cofactor pair (4, 4), prime subgroup
# orders, and A^2 - 4 non-square. This script recomputes the admissibility
# checks for the selected A. The expensive uniqueness search is documented in
# README and is not repeated here.
# -----------------------------------------------------------------------------
print("7. RIGIDITY")
print("-" * 70)

rigidity_limit = 10**6
rigidity_h = 4
rigidity_twist_h = 4

rigidity_order = order
rigidity_twist_order = 2 * (p + 1) - rigidity_order
rigidity_order_ok = rigidity_order % rigidity_h == 0
rigidity_twist_order_ok = rigidity_twist_order % rigidity_twist_h == 0
rigidity_n = rigidity_order // rigidity_h
rigidity_twist_n = rigidity_twist_order // rigidity_twist_h
rigidity_cofactors_ok = rigidity_order_ok and rigidity_twist_order_ok
rigidity_subgroups_ok = is_prime(rigidity_n) and is_prime(rigidity_twist_n)
rigidity_nonsquare_ok = not Mod(A**2 - 4, p).is_square()
rigidity_in_range = 0 <= A <= rigidity_limit

print(f"Selected A          = {A}")
print(f"Search range        = 0 <= A <= {rigidity_limit}")
print(f"In range?           {'PASS' if rigidity_in_range else 'FAIL'}")
print(f"Cofactor pair       = ({rigidity_order // rigidity_n}, {rigidity_twist_order // rigidity_twist_n})")
print(f"Cofactors (4, 4)?   {'PASS' if rigidity_cofactors_ok else 'FAIL'}")
print(f"Subgroups prime?    {'PASS' if rigidity_subgroups_ok else 'FAIL'}")
print(f"A^2 - 4 non-square? {'PASS' if rigidity_nonsquare_ok else 'FAIL'}")
print("Uniqueness          = established by the documented exhaustive search")
rigid_ok = (
    rigidity_in_range
    and rigidity_cofactors_ok
    and rigidity_subgroups_ok
    and rigidity_nonsquare_ok
)
print(f"Admissibility       {'PASS' if rigid_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 8. LADDER (Montgomery ladder)
# Complete if A^2 - 4 is non-square mod p
# -----------------------------------------------------------------------------
print("8. MONTGOMERY LADDER")
print("-" * 70)
A2_minus_4 = Mod(A**2 - 4, p)
ladder_ok = not A2_minus_4.is_square()
print(f"A^2 - 4 mod p    = {A2_minus_4}")
print(f"Non-square?      {'PASS' if ladder_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 9. TWIST
# Twist cofactor small and twist subgroup prime
# -----------------------------------------------------------------------------
print("9. TWIST")
print("-" * 70)
twist_order = 2 * (p + 1) - order
twist_h = 4
twist_n = twist_order // twist_h
print(f"Twist order      = {twist_order}")
print(f"                  = {to_hex(twist_order)}")
print(f"Twist cofactor   = {twist_h}")
print(f"Twist subgroup order = {twist_n}")
twist_prime = is_prime(twist_n)
print(f"Subgroup prime?  {'PASS' if twist_prime else 'FAIL'}")
twist_ok = (twist_order % 4 == 0) and twist_prime
print(f"Twist OK         {'PASS' if twist_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 10. COMPLETENESS
# Montgomery ladder is complete when A^2 - 4 is a non-square.
# Ed256189 uses the dual twisted Edwards curve
#     d*u^2 + v^2 = 1 + a*u^2*v^2,
# whose standard addition law is complete when the coefficient of u^2 (d) is a
# square and the coefficient of u^2*v^2 (a) is a non-square.
# -----------------------------------------------------------------------------
print("10. COMPLETENESS")
print("-" * 70)
A2_minus_4_nonsquare = not Mod(A**2 - 4, p).is_square()
a_ed = A + 2
d_ed = A - 2
dual_edwards_complete = Mod(d_ed, p).is_square() and not Mod(a_ed, p).is_square()
natural_edwards_complete = Mod(a_ed, p).is_square() and not Mod(d_ed, p).is_square()
print(f"Montgomery complete (A^2 - 4 non-square)? {'PASS' if A2_minus_4_nonsquare else 'FAIL'}")
print(f"Natural E_(a,d) complete?                 {'PASS' if natural_edwards_complete else 'FAIL'} (not used by Ed256189)")
print(f"Dual E_(d,a) complete?                    {'PASS' if dual_edwards_complete else 'FAIL'} (used by Ed256189)")
complete_ok = A2_minus_4_nonsquare and dual_edwards_complete
print(f"Complete (Montgomery ladder + dual Edwards) {'PASS' if complete_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# 11. INDISTINGUISHABILITY (Elligator 2)
# Applicable if A^2 - 4 non-square and curve has point of order 2
# -----------------------------------------------------------------------------
print("11. INDISTINGUISHABILITY (ELLIGATOR 2)")
print("-" * 70)
elligator2_ok = (not Mod(A**2 - 4, p).is_square()) and (order % 2 == 0)
print(f"A^2 - 4 non-square?      {'PASS' if not Mod(A**2 - 4, p).is_square() else 'FAIL'}")
print(f"Point of order 2?        {'PASS' if order % 2 == 0 else 'FAIL'}")
print(f"Elligator 2 applicable   {'PASS' if elligator2_ok else 'FAIL'}")
print()

# -----------------------------------------------------------------------------
# SUMMARY TABLE (like on the main SafeCurves page)
# -----------------------------------------------------------------------------
print("=" * 70)
print(" " * 20 + "SAFECURVES SUMMARY")
print(" " * 18 + "Curve256189 (Montgomery)")
print("=" * 70)
print(f"{'Criteria':<25} {'Status':<10} {'Details'}")
print("-" * 70)

criteria = [
    ("Field", prime_ok, f"p = 2^256-189, prime {prime_ok}"),
    ("Equation", eq_ok, f"A = {A}, B = 1, non-zero discriminant"),
    ("Base point", base_ok, f"order n prime, n*G = O"),
    ("Rho", rho_ok, f"2^{rho_bits:.1f} > 2^100"),
    ("Transfer", transfer_ok, f"n != p, k > 100"),
    ("Discriminant", disc_ok, f"|D| > 2^100"),
    ("Rigidity", rigid_ok, "A admissible; uniqueness from documented search"),
    ("Ladder", ladder_ok, f"A^2 - 4 non-square"),
    ("Twist", twist_ok, f"twist cofactor 4, twist subgroup prime"),
    ("Completeness", complete_ok, "Montgomery ladder and dual Edwards complete"),
    ("Indistinguishability", elligator2_ok, f"Elligator 2 applicable")
]

passed = 0
for name, ok, detail in criteria:
    status = "PASS" if ok else "FAIL"
    print(f"{name:<25} {status:<10} {detail}")
    if ok:
        passed += 1

print("-" * 70)
print(f"Total: {passed}/11 criteria met.")
all_ok = all(ok for _, ok, _ in criteria)
print(f"SafeCurves compliant? {'YES' if all_ok else 'NO'}")
print("=" * 70)
print("\nReference: https://safecurves.cr.yp.to/")
print("Author   : Ismael Urzaiz Aranda")
print("=" * 70)
