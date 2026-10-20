# find the smallest c where p = 2^256 - c is prime
# Change to 256

for c in range(1,1000):
    p = 2^256 - c
    if is_prime(p):
        print("Prime found!")
        print("c =", c)
        print("p =", p)
        break