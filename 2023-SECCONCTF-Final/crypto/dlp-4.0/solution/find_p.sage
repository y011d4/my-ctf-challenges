while True:
    p = 2*randint(0, 2**28)**12 - 1
    if p.nbits() != 333:
        continue
    if not is_prime(p):
        continue
    print(p)
    max_bits = max(factor(p**2-1))[0].nbits()
    print(max_bits)
    if max_bits <= 36:
        break
