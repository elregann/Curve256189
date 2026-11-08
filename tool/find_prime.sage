# =============================================================================
# Prime Search - Curve256189
# Find the smallest c such that p = 2^256 - c is prime.
# Expected result: c = 189, p = 2^256 - 189.
# =============================================================================

FIELD_BITS = 256
SEARCH_LIMIT = 1000

for c in range(1, SEARCH_LIMIT):
    p = 2**FIELD_BITS - c
    if is_prime(p):
        print("Prime found!")
        print("c =", c)
        print("p =", p)
        break
