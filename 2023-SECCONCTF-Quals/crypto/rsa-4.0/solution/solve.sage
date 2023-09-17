from Crypto.Util.number import long_to_bytes


with open("output.txt") as fp:
    exec(fp.readline())  # n
    exec(fp.readline())  # e
    Q = QuaternionAlgebra(Zmod(n), -1, -1)
    i, j, k = Q.gens()
    exec(fp.readline())  # enc

# recover p, q
mat = matrix(QQ, [[3, 1, 337], [3, 13, 37], [7, 133, 7]])
vec = vector(QQ, [0, 1, 0])
res = mat.solve_left(vec)
res *= res.denominator()
p_mul = res * vector(QQ, [enc[1], enc[2], enc[3]])
p = int(gcd(n, p_mul))
assert n % p == 0
q = n // p

# solution 1: find the multiplicative order
phi = (p**2 - 1) * (q**2 - 1)
d = pow(e, -1, phi)
m = int((enc**d)[0])
print(long_to_bytes(m).decode())

# solution 2: use the linear relation shown above
m = int(
    (enc[2] * (p + 337 * q) - enc[1] * (13 * p + 37 * q))
    * pow(3 * (enc[1] - enc[2]), -1, n)
    % n
)
print(long_to_bytes(m).decode())
