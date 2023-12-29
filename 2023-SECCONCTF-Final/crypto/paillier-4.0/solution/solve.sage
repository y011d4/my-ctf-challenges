import re
from Crypto.Util.number import bytes_to_long, long_to_bytes

with open("./output.txt") as fp:
    for _ in range(2):
        _ = fp.readline()
    c_m1_list = list(map(int, re.findall(r"c1 = (\d+) \+ (\d+)\*i \+ (\d+)\*j \+ (\d+)\*k", fp.readline().strip())[0]))
    c_m2_list = list(map(int, re.findall(r"c2 = (\d+) \+ (\d+)\*i \+ (\d+)\*j \+ (\d+)\*k", fp.readline().strip())[0]))

m1 = bytes_to_long(b"I have implemented Paillier 4.0. Can you break it?")
n = gcd(c_m1_list[1:])
for prime in prime_range(10000):
    while n % prime == 0:
        n //= prime

Q = QuaternionAlgebra(Zmod(n**2), -1, -1)
i, j, k = Q.gens()
c_m1 = Q(c_m1_list)
c_m2 = Q(c_m2_list)
c1 = c_m1 ** pow(m1, -1, n)

g_ = c1 * pow(c1[0], -1, n)  # g_ == g mod n
mk = (int(c_m2[1]) // n) * pow(int(g_[1]) // n, -1, n**2) % n
k = (c_m2[0] - (g_[0] - 1) * mk) % n
m = mk * pow(k, -1, n) % n

print(long_to_bytes(int(m)))
