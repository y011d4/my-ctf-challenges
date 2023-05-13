def genprime(m):
    while True:
        x = randint(2**383, 2**384)
        y = randint(2**255, 2**256)
        p = x ** 2 + m * y ** 2
        if is_prime(p) and p.nbits() == 768:
            return p, x, y


while True:
    e = random_prime(2**256, lbound=2**255)
    p, xp, yp = genprime(e)
    q, xq, yq = genprime(e)
    n = p * q
    x1 = abs(xp * xq + e * yp * yq)
    y1 = abs(xp * yq - xq * yp)
    assert n == x1 ** 2 + e * y1 ** 2
    x2 = abs(xp * xq - e * yp * yq)
    y2 = abs(xp * yq + xq * yp)
    assert n == x2 ** 2 + e * y2 ** 2
    if x1.bit_length() <= 768 and y1.bit_length() <= 640 and x2.bit_length() <= 768 and y2.bit_length() <= 640:
        break
print(f"{p = }")
print(f"{q = }")
print(f"{x1 = }")
print(f"{y1 = }")
print(f"{x2 = }")
print(f"{y2 = }")
print(f"{e = }")
print('flag = b"HackTM{r07473_pr353rv35_50m37h1n6}"')
