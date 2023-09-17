import os
from functools import reduce
from secrets import randbelow


p1 = 21267647932558653966460912964485513283
a1 = 6701852062049119913950006634400761786
b1 = 19775891958934432784881327048059215186
p2 = 21267647932558653966460912964485513289
a2 = 10720524649888207044145162345477779939
b2 = 19322437691046737175347391539401674191
p3 = 21267647932558653966460912964485513327
a3 = 8837701396379888544152794707609074012
b3 = 10502852884703606118029748810384117800


def prod(x: list[int]) -> int:
    return reduce(lambda a, b: a * b, x, 1)


def xor(x: bytes, y: bytes) -> bytes:
    return bytes([xi ^^ yi for xi, yi in zip(x, y)])


class ICG:
    def __init__(self, p: int, a: int, b: int) -> None:
        self.p = p
        self.a = a
        self.b = b
        self.x = randbelow(self.p)

    def _next(self) -> int:
        if self.x == 0:
            self.x = self.b
            return self.x
        else:
            self.x = (self.a * pow(self.x, -1, self.p) + self.b) % self.p
            return self.x

    def _prev(self) -> int:
        self.x = pow(self.x - self.b, -1, self.p) * self.a % self.p
        return self.x


class CIG:
    L = 256

    def __init__(self, icgs: list[ICG]) -> None:
        self.icgs = icgs
        self.T = prod([icg.p for icg in self.icgs])
        self.Ts = [self.T // icg.p for icg in self.icgs]

    def _next(self) -> int:
        ret = 0
        for icg, t in zip(self.icgs, self.Ts):
            ret += icg._next() * t
            ret %= self.T
        return ret % 2**self.L

    def _prev(self) -> int:
        ret = 0
        for icg, t in zip(self.icgs, self.Ts):
            ret += icg._prev() * t
            ret %= self.T
        return ret % 2**self.L

    def randbytes(self, n: int) -> bytes:
        ret = b""
        byte_size = self.L // 8
        while n > 0:
            ret += int(self._next()).to_bytes(byte_size, "big")[: min(n, byte_size)]
            n -= byte_size
        return ret



with open("output.txt") as fp:
    exec(fp.readline())  # enc_flag
    exec(fp.readline())  # leaked

trunc_rands = []
for i in range(0, len(leaked), 32):
    trunc_rands.append(int.from_bytes(leaked[i: i+32], "big"))
trunc_rands.pop()



# z_i: i-th output of CGI (not truncated)
# xj_i: i-th output of j-th ICG (not truncated)
# k_i: unknown bits of z_i
# r_i: known bits of z_i

# Consider mod p1, p2, p3:
# z_i * pow(p2*p3, -1, p1) = x1_i mod p1
# z_i * pow(p3*p1, -1, p2) = x2_i mod p2
# z_i * pow(p1*p2, -1, p3) = x3_i mod p3

# In the following only consider x1. Since z_i = 2**L * k_i + r_i:
# (k_i * 2**L + r_i) * pow(p2*p3, -1, p1) = x1_i mod p1
# (k_i + r_i * 2^-L) * pow(p2*p3, -1, p1) * 2^L = x1_i mod p1

# Substitute it for a1 + b1 * x1_i - x1_i * x1_{i+1} == 0 mod p1 (this is derived from a1/x1_i + b1 == x1_{i+1}):
# a1 + b1 * (r_i * 2^-L + k_i) * pow(p2*p3, -1, p1) * 2^L - (r_i * 2^-L + k_i) * (r_{i+1} * 2^-L + k_{i+1}) * pow(p2*p3, -2, p1) * 2^(2*L) == 0 mod p1
# a1 + b1 * r_i * pow(p2*p3, -1, p1) + b1 * pow(p2*p3, -1, p1) * 2^L * k_i - r_i * r_{i+1} * pow(p2*p3, -2, p1) - r_i * 2^L * pow(p2*p3, -2, p1) * k_{i+1} - r_{i+1} * 2^L * pow(p2*p3, -2, p1) * k_i - pow(p2*p3, -2, p1) * 2^(2*L) * k_i * k_{i+1} == 0 mod p1
L = 256
T = p1 * p2 * p3
N = len(trunc_rands) - 1
# [0, ..., 0, 0, ..., 0, 0, ..., 0, k_1, ..., k_{N+1}, k_1*k_2, ..., k_N*k_{N+1}, 1] = [lp1_1, ..., lp1_N, lp2_1, ..., lp2_N, lp3_1, ..., lp3_N, k_1, ..., k_{N+1}, k_1*k_2, ..., k_N*k_{N+1}, 1] * mat
mat = matrix(ZZ, 5*N+2, 5*N+2)
for i in range(N):
    mat[i, i] = -p1
    mat[3*N+i, i] = b1 * pow(p2*p3, -1, p1) * 2^L - trunc_rands[i+1] * 2^L * pow(p2*p3, -2, p1)
    mat[3*N+1+i, i] = - trunc_rands[i] * 2^L * pow(p2*p3, -2, p1)
    mat[4*N+1+i, i] = -pow(p2*p3, -2, p1) * 2^(2*L)
    mat[5*N+1, i] = a1 + b1 * trunc_rands[i] * pow(p2*p3, -1, p1) - trunc_rands[i] * trunc_rands[i+1] * pow(p2*p3, -2, p1)
for i in range(N):
    mat[N+i, N+i] = -p2
    mat[3*N+i, N+i] = b2 * pow(p3*p1, -1, p2) * 2^L - trunc_rands[i+1] * 2^L * pow(p3*p1, -2, p2)
    mat[3*N+1+i, N+i] = - trunc_rands[i] * 2^L * pow(p3*p1, -2, p2)
    mat[4*N+1+i, N+i] = -pow(p3*p1, -2, p2) * 2^(2*L)
    mat[5*N+1, N+i] = a2 + b2 * trunc_rands[i] * pow(p3*p1, -1, p2) - trunc_rands[i] * trunc_rands[i+1] * pow(p3*p1, -2, p2)
for i in range(N):
    mat[2*N+i, 2*N+i] = -p3
    mat[3*N+i, 2*N+i] = b3 * pow(p1*p2, -1, p3) * 2^L - trunc_rands[i+1] * 2^L * pow(p1*p2, -2, p3)
    mat[3*N+1+i, 2*N+i] = - trunc_rands[i] * 2^L * pow(p1*p2, -2, p3)
    mat[4*N+1+i, 2*N+i] = -pow(p1*p2, -2, p3) * 2^(2*L)
    mat[5*N+1, 2*N+i] = a3 + b3 * trunc_rands[i] * pow(p1*p2, -1, p3) - trunc_rands[i] * trunc_rands[i+1] * pow(p1*p2, -2, p3)
for i in range(N+1):
    mat[3*N+i, 3*N+i] = 1
for i in range(N):
    mat[4*N+1+i, 4*N+1+i] = 1
mat[5*N+1, 5*N+1] = 1
weights = diagonal_matrix([int(sqrt(5*N+2) * (T//2**L)**2)] * (3*N) + [T//2**L] * (N+1) + [1] * N + [int(sqrt(5*N+2) * (T//2**L)**2)])
mat *= weights
C = mat.LLL()
C /= weights
mat /= weights

assert C[-1, 5*N+1] == 1
x = trunc_rands[0] + 2**L * int(C[-1][3*N])
x1 = (x % p1) * pow(p2*p3, -1, p1) % p1
x2 = (x % p2) * pow(p3*p1, -1, p2) % p2
x3 = (x % p3) * pow(p1*p2, -1, p3) % p3

random = CIG([ICG(p1, a1, b1), ICG(p2, a2, b2), ICG(p3, a3, b3)])
random.icgs[0].x = x1
random.icgs[1].x = x2
random.icgs[2].x = x3
for _ in range(2+(len(enc_flag)-1)//32):
    random._prev()
flag = xor(enc_flag, random.randbytes(len(enc_flag))).decode()
print(flag)
