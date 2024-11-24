import hashlib
from functools import partial
from multiprocessing import Pool

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pwn import remote
from tqdm import tqdm

from lll_cvp import *


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
E = EllipticCurve(GF(P), [A, B])
G = E(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
n = G.order()

primes = []
for prime in prime_range(3, 2**20):
    primes.append(prime)
    if prod(primes) > 2**256:
        for prime in primes[::-1]:
            if int(prod(filter(lambda x: x != prime, primes))).bit_length() == 256:
                primes.remove(prime)
                break
        break
p = prod(primes)
assert p % 3 == 0 and p % 11 == 0

M = 90
Ts = [3, 11]
T = prod(Ts)
N = M * T
z = int.from_bytes(hashlib.sha1(b"").digest(), "big")


def get_signatures():
    io = remote("localhost", int(13337))

    io.sendlineafter(b"(hex) > ", hex(p).encode())

    io.sendlineafter(b"option > ", b"2")
    io.recvuntil(b"pubkey = ")
    ret = bytes.fromhex(io.recvline().strip().decode())
    pub = E(int.from_bytes(ret[:32], "big"), int.from_bytes(ret[32:], "big"))

    io.sendlineafter(b"option > ", b"3")
    io.recvuntil(b"enc = ")
    enc = bytes.fromhex(io.recvline().strip().decode())

    for _ in range(N):
        io.sendline(b"1")
        io.sendline(b"")

    rs = []
    ss = []
    for _ in tqdm(range(N)):
        _ = io.recvuntil(b"signature = ")
        signature = bytes.fromhex(io.recvline().strip().decode())
        rs.append(int.from_bytes(signature[:32], "big"))
        ss.append(int.from_bytes(signature[32:], "big"))

    io.close()
    return pub, enc, rs, ss


def preprocess(pub, rs, ss):
    """
    We have r, s such that:
        k = s^-1 * z + s^-1 * r * d
    To use them for the solver which requires known upper bits, we process r, s into r', s', k'.
    When k = 11[01]{252}11, let k' = (2^256-1-k)/4.
        4 * k' = 2**256 - 1 - k = 2**256 - 1 - s^-1 * z - s^-1 * r * d
    Comparing this with k' = s'^-1 * z' + s'^-1 * r' * d,
        s'^-1 * z' = 4^-1 * (2**256 - 1 - s^-1 * z)
        s'^-1 * r' = 4^-1 * (- s^-1 * r)
        r' = (k' * G).x()
    """
    new_rsz_list = []
    for base in tqdm(range(0, T)):
        new_rs = []
        new_ss = []
        new_zs = []
        for i in range(base, base + T * M, T):
            for R in E.lift_x(Integer(rs[i]), all=True):
                r_ = int((pow(4, -1, n) * (2**256 - 1) * G - pow(4, -1, n) * R).x())
                s_ = int((-r_ * ss[i] * pow(rs[i], -1, n) * 4) % n)
                z_ = int(pow(4, -1, n) * s_ * (2**256 - 1 - pow(ss[i], -1, n) * z) % n)
                w_ = pow(s_, -1, n)
                u1_ = int(z_ * w_ % n)
                u2_ = int(r_ * w_ % n)
                if (u1_ * G + u2_ * pub).x() == r_:
                    break
            else:
                raise RuntimeError
            new_rs.append(r_)
            new_ss.append(s_)
            new_zs.append(z_)
        new_rsz_list.append((pub, new_rs, new_ss, new_zs))
    return new_rsz_list


def recover_d_each(arg):
    # k = s^-1 * (z + r * d) % n
    # [k1 - s^-1*z, ..., kM - s^-1*z, d] = [l1, ..., lM, d] * mat
    pub, rs, ss, zs = arg
    mat = matrix(ZZ, M+1, M+1)
    lb = []
    ub = []
    for i in range(M):
        mat[i, i] = -n
        mat[M, i] = pow(ss[i], -1, n) * rs[i] % n
        lb.append(-(pow(ss[i], -1, n) * zs[i] % n))
        ub.append(2**252-pow(ss[i], -1, n) * zs[i] % n)
    mat[M, M] = 1
    lb.append(0)
    ub.append(n)
    res = solve_inequality(
        mat,
        lb,
        ub,
        cvp=partial(kannan_cvp, reduction=lambda M: M.BKZ(block_size=25), weight=None),
    )
    if res[-1] * G == pub:
        return int(res[-1])
    else:
        return None


def recover_bits(d, rs, ss):
    ks = []
    for r, s in zip(rs, ss, strict=True):
        k = pow(s, -1, n) * (z + r * d) % n
        ks.append(k)
    return list(map(lambda x: int(x), "".join([f"{k:0256b}" for k in ks])))


def recover_a(bits):
    a_list = []
    b_list = []
    for prime in tqdm(primes):
        cands = []
        for i in range(prime):
            if all([b == 1 for b in bits[:20000][i::prime]]):
                cands.append(i)
        if len(cands) == 1:
            print(prime, cands)
            a_list.append(prime - cands[0])
            b_list.append(prime)
    return int(crt(a_list, b_list))


def solve():
    while True:
        pub, enc, rs, ss = get_signatures()
        new_rsz_list = preprocess(pub, rs, ss)
        with Pool(9) as pool:
            res = pool.map(recover_d_each, new_rsz_list)
        print(res)
        res = list(filter(lambda x: x is not None, res))
        if len(res) == 0:
            print("retry")
        else:
            d = res[0]
            break
    bits = recover_bits(d, rs, ss)
    a = recover_a(bits)
    key = int(d ^^ a).to_bytes(32, "big")
    print(unpad(AES.new(key, AES.MODE_ECB).decrypt(enc), 16).decode())


if __name__ == "__main__":
    solve()
