import re
from itertools import product
from Crypto.Util.number import long_to_bytes

F = RealField(1337)

with open("./output.txt") as fp:
    n = int(re.findall(r"n = (.*)", fp.readline().strip())[0])
    c = int(re.findall(r"c = (.*)", fp.readline().strip())[0])
    xstr = re.findall(r"x = \((.*), (.*)\)", fp.readline().strip())[0]
    x = [F(xstr[0]), F(xstr[1])]
    ystr = re.findall(r"y = \((.*), (.*)\)", fp.readline().strip())[0]
    y = [F(ystr[0]), F(ystr[1])]


# find p, q
d = x[0] * y[1] - x[1] * y[0]
PR.<offset> = PolynomialRing(Zmod(n))
f = int(d) + offset
tmp = int(int(d) + f.small_roots(beta=0.495, epsilon=0.03)[0])
p = int(gcd(n, tmp))
assert n % p == 0
q = n // p
print(f"[+] {p = }")
print(f"[+] {q = }")

# find e
e = int((2 * n - int(x[0] ** 2 + x[1] ** 2)) / int(y[0] ** 2 + y[1] ** 2))
for offset in range(-3, 4):
    if is_prime(e + offset):
        e = e + offset
        break
assert e.bit_length() == 256
print(f"[+] {e = }")


# find x1, x2, y1, y2
# https://people.math.carleton.ca/~williams/papers/pdf/202.pdf
f = 1
g = e
PR.<zp> = PolynomialRing(Zmod(p))
rootsp = (f * zp**2 + g).roots()
PR.<zq> = PolynomialRing(Zmod(q))
rootsq = (f * zq**2 + g).roots()

roots = []
for (rootp, _), (rootq, _) in product(rootsp, rootsq):
    roots.append(int(crt([int(rootp), int(rootq)], [p, q])))
roots = list(filter(lambda x: x <= n // 2, roots))
assert len(roots) == 2

uvs = []
ub = int(sqrt(n / f))
for z in roots:
    x, y = n, int(z)
    while True:
        if y <= ub:
            break
        x, y = y, int(x % y)
    rz = y
    u = rz
    v = sqrt((n - f * rz**2) // g)
    uvs.append((u, v))
assert len(uvs) == 2
print(f"[+] (x1, y1) = ({uvs[0][0]}, {uvs[0][1]})")
print(f"[+] (x2, y2) = ({uvs[1][0]}, {uvs[1][1]})")

d = pow(e, -1, (p - 1) * (q - 1))
flag = long_to_bytes(pow(c, d, n) ^^ uvs[0][0] ^^ uvs[0][1] ^^ uvs[1][0] ^^ uvs[1][1]).decode()
print(f"{flag = }")
