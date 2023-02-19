from binascii import unhexlify
from collections import defaultdict
from hashlib import sha256
from random import SystemRandom

from Crypto.Util.number import bytes_to_long, long_to_bytes

from pwn import remote


random = SystemRandom()

q = 8383489
b = 16383
w = 3
PR = PolynomialRing(Zmod(q), name="x")
x = PR.gens()[0]
n = 420
phi = x**n - 1
Rq = PR.quotient(phi, "x")
x = Rq.gens()[0]


def sample(K):
    poly = 0
    for i in range(n):
        poly += random.randint(-K, K) * x**i
    return poly


def polyhash(poly, m):
    h = sha256()
    for i in range(n):
        h.update(long_to_bytes(int(poly[i]), 3))
    h.update(m)
    return h.digest()


def hash2poly(h):
    hash_int = bytes_to_long(h)
    poly = 0
    for i in range(n):
        poly += ((1 << i) & hash_int != 0) * x**i
    return poly


def keygen(a):
    s = sample(1)
    e = sample(1)
    t = a * s + e
    r = (s, e)
    return r, t


def sign(m, r, t, a):
    s, e = r
    while True:
        y1 = sample(b)
        y2 = sample(b)
        c_ = polyhash(a * y1 + y2, m)
        c = hash2poly(c_)
        z1 = s * c + y1
        z2 = e * c + y2
        valid = True
        for i in range(n):
            if b - w < z1[i] < q - (b - w) or b - w < z2[i] < q - (b - w):
                valid = False
                break
        if valid:
            break
    return z1, z2, c


def verify(m, sig, t, a):
    z1, z2, c = sig
    for i in range(n):
        if min(z1[i], q - z1[i]) > b - w:
            return False
        if min(z2[i], q - z2[i]) > b - w:
            return False
    d_ = polyhash(a * z1 + z2 - t * c, m)
    d = hash2poly(d_)
    return d == c


def encode_poly(poly):
    enc = b""
    for i in range(n):
        enc += long_to_bytes(int(poly[i]), 3)
    return enc


def decode_poly(poly_enc):
    assert len(poly_enc) == 3 * n
    enc = b""
    poly = 0
    for i in range(0, 3 * n, 3):
        poly += bytes_to_long(poly_enc[i: i+3]) * x ** (i // 3)
    return poly



Y.<y> = ZZ[]

def offset_poly(poly):
    new_poly = Y(0)
    for i in range(n):
        new_poly += (int(poly[i]) if poly[i] < q // 2 else -int(q - poly[i])) * y ** i
    return new_poly


def find_s_e(a, t, mod_poly):
    tmp_a = offset_poly(a) % mod_poly
    tmp_t = offset_poly(t) % mod_poly
    tmp_n = mod_poly.degree()
    mod_coeffs = list(map(lambda x: int(-x), mod_poly.list()[:tmp_n]))
    mod_idx_to_coeff = {idx: coeff for idx, coeff in enumerate(mod_coeffs) if coeff != 0}
    # [-e0, ..., -e419, s0, ..., s419, 1] = [s0, ..., s419, k0, ..., k419, 1] * mat
    mat = matrix(ZZ, 2*tmp_n+1, 2*tmp_n+1)
    for sa_idx in range(2 * tmp_n - 1):
        if sa_idx >= tmp_n:
            idx_to_coeff = defaultdict(int)
            idx_to_coeff[sa_idx] = 1
            while max(idx_to_coeff) >= tmp_n:
                max_idx = max(idx_to_coeff)
                max_coeff = idx_to_coeff[max_idx]
                del idx_to_coeff[max_idx]
                for mod_idx, mod_coeff in mod_idx_to_coeff.items():
                    idx_to_coeff[max_idx-tmp_n+mod_idx] += max_coeff * mod_coeff
            for s_idx in range(sa_idx - tmp_n + 1, tmp_n):
                a_idx = sa_idx - s_idx
                assert 0 <= s_idx < tmp_n and 0 <= a_idx < tmp_n
                for idx, coeff in idx_to_coeff.items():
                    mat[s_idx, idx] += coeff * tmp_a[a_idx]
        else:
            for s_idx in range(sa_idx + 1):
                a_idx = sa_idx - s_idx
                assert 0 <= a_idx < tmp_n
                mat[s_idx, sa_idx] += tmp_a[a_idx]
    for i in range(tmp_n):
        mat[tmp_n+i, i] = q
    for i in range(tmp_n):
        mat[i, tmp_n+i] = 1
    t_list = list(map(int, tmp_t.list()))
    for i in range(tmp_n):
        mat[2*tmp_n, i] = -t_list[i]
    mat[2*tmp_n, 2*tmp_n] = 1
    L = mat.LLL()
    ans = L[0]
    assert ans[-1] == 1
    tmp_s = 0
    for i in range(tmp_n):
        tmp_s += int(ans[tmp_n+i]) * y**i
    tmp_e = 0
    for i in range(tmp_n):
        tmp_e += int(-ans[i]) * y**i
    return tmp_s, tmp_e


io = remote("34.141.16.87", int(50002))

_ = io.recvuntil(b"a_enc = ")
a_enc = unhexlify(io.recvline().strip().decode())
a = decode_poly(a_enc)
_ = io.recvuntil(b"t_enc = ")
t_enc = unhexlify(io.recvline().strip().decode())
t = decode_poly(t_enc)

s_list = []
e_list = []
mod_list = []
polys = [tmp for tmp, _ in factor(y ** n - 1)]
for i in range(len(polys)):
    mod_poly = polys[i]
    print(mod_poly)
    tmp_s, tmp_e = find_s_e(a, t, mod_poly)
    s_list.append(tmp_s)
    e_list.append(tmp_e)
    mod_list.append(mod_poly)

s = Rq(crt(s_list, list(map(lambda x: x.change_ring(QQ), mod_list))))
e = Rq(crt(e_list, list(map(lambda x: x.change_ring(QQ), mod_list))))
m = b"sign me!"
z1, z2, c = sign(m, (s, e), t, a)
assert verify(m, (z1, z2, c), t, a)
io.sendlineafter(b"z1 = ", encode_poly(z1).hex().encode())
io.sendlineafter(b"z2 = ", encode_poly(z2).hex().encode())
io.sendlineafter(b"c = ", encode_poly(c).hex().encode())
print(io.recvline().strip())
