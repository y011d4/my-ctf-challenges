from dataclasses import dataclass
from typing import List, Tuple
import gmpy2
from pwn import remote, context
from Crypto.Util.number import long_to_bytes


def crt(r1: int, n1: int, r2: int, n2: int) -> int:
    g, x, y = gmpy2.gcdext(n1, n2)
    assert g == 1
    return int((n1 * x * r2 + n2 * y * r1) % (n1 * n2))


@dataclass
class Pubkey:
    n: int
    c: int


@dataclass
class Privkey:
    p: int
    q: int


@dataclass
class Enc:
    r: int
    s: int
    t: int

    def __repr__(self) -> str:
        return f"r = {self.r}\ns = {self.s}\nt = {self.t}"


def recv_r_s_t(io: remote):
    ret = io.recvline().strip().decode()
    if "wrong" in ret:
        return None, None, None
    _ = io.recvuntil(b"r = ")
    r = int(io.recvline())
    _ = io.recvuntil(b"s = ")
    s = int(io.recvline())
    _ = io.recvuntil(b"t = ")
    t = int(io.recvline())
    return r, s, t


def oracle(r: int, s: int, t: int, io: remote):
    io.sendlineafter(b"r, s, t = ", f"{r}, {s}, {t}".encode())
    return recv_r_s_t(io)


def solve_quad(r: int, c: int, p: int) -> Tuple[int, int]:
    """
    Solve x^2 - r * x + c = 0 mod p
    See chapter 5.
    """

    def mod(poly: List[int]) -> None:
        """
        Calculate mod x^2 - r * x + c (inplace)
        """
        assert len(poly) == 3
        if poly[2] == 0:
            return
        poly[1] += poly[2] * r
        poly[1] %= p
        poly[0] -= poly[2] * c
        poly[0] %= p
        poly[2] = 0

    def prod(poly1: List[int], poly2: List[int]) -> List[int]:
        """
        Calculate poly1 * poly2 mod x^2 - r * x + c
        """
        assert len(poly1) == 3 and len(poly2) == 3
        assert poly1[2] == 0 and poly2[2] == 0
        res = [
            poly1[0] * poly2[0] % p,
            (poly1[1] * poly2[0] + poly1[0] * poly2[1]) % p,
            poly1[1] * poly2[1] % p,
        ]
        mod(res)
        assert res[2] == 0
        return res

    # calculate x^exp mod (x^2 - r * x + c) in GF(p)
    exp = (p - 1) // 2
    res_poly = [1, 0, 0]  # = 1
    cur_poly = [0, 1, 0]  # = x
    while True:
        if exp % 2 == 1:
            res_poly = prod(res_poly, cur_poly)
        exp //= 2
        if exp == 0:
            break
        cur_poly = prod(cur_poly, cur_poly)

    # I think the last equation in chapter 5 should be x^{(p-1)/2}-1 mod (x^2 - Ex + c)
    # (This change is not related to vulnerability as far as I know)
    a1 = -(res_poly[0] - 1) * pow(res_poly[1], -1, p) % p
    a2 = (r - a1) % p
    return a1, a2


def decrypt(enc: Enc, pub: Pubkey, priv: Privkey) -> int:
    assert 0 <= enc.r < pub.n
    assert enc.s in [1, -1]
    assert enc.t in [0, 1]
    mps = solve_quad(enc.r, pub.c, priv.p)
    mqs = solve_quad(enc.r, pub.c, priv.q)
    ms = []
    for mp in mps:
        for mq in mqs:
            m = crt(mp, priv.p, mq, priv.q)
            if gmpy2.jacobi(m, pub.n) == enc.s:
                ms.append(m)
    assert len(ms) == 2
    m1, m2 = ms
    if m1 < m2:
        m1, m2 = m2, m1
    if enc.t == 1:
        m = m1
    elif enc.t == 0:
        m = m2
    else:
        raise ValueError
    return m


io = remote("34.141.16.87", int(50001))
enc_r, enc_s, enc_t = recv_r_s_t(io)
res = []
for i in range(1, 21):
    rst = oracle(i, 1, 1, io)
    if rst[0] is None:
        continue
    res.append(rst[0] - i)

factors = set()
for i in range(len(res)):
    if res[i] == 0:
        continue
    for j in range(i + 1, len(res)):
        if res[j] == 0:
            continue
        tmp = gcd(res[i], res[j])
        if tmp > 2**100:
            for pi in prime_range(1000):
                while True:
                    if tmp % pi == 0:
                        tmp //= pi
                    else:
                        break
            factors.add(tmp)
assert len(factors) == 2
p = int(factors.pop())
q = int(factors.pop())
n = p * q
print(f"[+] Recover p, q, n:\n{p = }\n{q = }\n{n = }")

r = None
for i in range(100):
    rst = oracle(i, 1, 1, io)
    if rst[0] is None:
        continue
    if gcd(rst[0] - i, n) == 1:
        r = i
        break
assert r is not None

rs = []
for s in [-1, 1]:
    for t in [0, 1]:
        rs.append(oracle(r, s, t, io)[0])
for i in range(4):
    for j in range(i + 1, 4):
        r1 = rs[i]
        r2 = rs[j]
        try:
            m1 = (r2 * r - r ** 2) * pow(r1 - 2 * r + r2, -1, n) % n
            c = (r1 * m1 - m1 ** 2) % n
            print(long_to_bytes(decrypt(Enc(r=enc_r, s=enc_s, t=enc_t), Pubkey(n=n, c=c), Privkey(p=p, q=q))))
        except Exception as e:
            print(e)
            continue
