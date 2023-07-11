import os
import random

from pwn import remote


N = 10000


class XorShiftPlus:
    A = 10
    B = 15
    C = 7
    L = 23

    def __init__(self) -> None:
        self.x = int(os.urandom(4).hex(), 16)
        self.y = int(os.urandom(4).hex(), 16)

    def gen32(self) -> int:
        t = self.x
        s = self.y
        self.x = s
        t ^^= (t << self.A) & 0xFFFFFFFF
        t ^^= t >> self.B
        t ^^= s ^^ (s >> self.C)
        self.y = t
        return (s + t) & 0xFFFFFFFF

    def random(self) -> float:
        n32 = self.gen32()
        nL = 0
        # only L bits are used for 32-bit floating point
        for _ in range(self.L):
            nL *= 2
            nL += n32 & 1
            n32 >>= 1
        return nL / 2**self.L


def rand_to_vec(rand):
    x_bits = f"{rand.x:032b}"[::-1]
    y_bits = f"{rand.y:032b}"[::-1]
    return vector(GF(2), map(int, x_bits + y_bits))


def vec_to_rand(vec):
    x = sum(2 ** i * b for i, b in enumerate(vec[:32].change_ring(ZZ)))
    y = sum(2 ** i * b for i, b in enumerate(vec[32:64].change_ring(ZZ)))
    rand = XorShiftPlus()
    rand.x = x
    rand.y = y
    return rand


def simulate(rand: XorShiftPlus) -> bool:
    a = rand.random()
    b = rand.random()
    r2 = a**2 + b**2
    return r2 < 1


def check(vec, result):
    rand = vec_to_rand(vec)
    for i in range(30):
        tmp = simulate(rand)
        if tmp and result[i] == "x":
            return False
        elif not tmp and result[i] == "o":
            return False
    return True


A = XorShiftPlus.A
B = XorShiftPlus.B
C = XorShiftPlus.C
L = matrix(GF(2), 32, 32)
R = matrix(GF(2), 32, 32)
I = matrix(GF(2), 32, 32)
for i in range(31):
    L[i, i+1] = 1
    R[i+1, i] = 1
for i in range(32):
    I[i, i] = 1

M = matrix(GF(2), 64, 64)
M[32:64, 0:32] = I
M01 = (I + L ** A) * (I + R ** B)
M11 = I + R ** C
M[0:32, 32:64] = M01
M[32:64, 32:64] = M11

O = matrix(GF(2), 64, 2 * N)
tmp = vector(GF(2), [1] + [0] * 31 + [1] + [0] * 31)
for i in range(2 * N):
    tmp = M * tmp
    O[:, i] = tmp

io = remote("localhost", int(50000))
result = io.recvline().strip().decode()

target_idx_list = []
for i in range(N):
    if result[i] == "x":
        target_idx_list += [2 * i + 0, 2 * i + 1]

vec = vector(GF(2), [1] * 64)
while True:
    idx_list = random.sample(target_idx_list, k=64)
    mat = O[:, idx_list]
    try:
        v = mat.solve_left(vec)
    except ValueError:
        continue
    K = mat.left_kernel()
    found = False
    for sol in [k + v for k in K]:
        if check(sol, result):
            found = True
            break
    if found:
        break

rand = vec_to_rand(sol)
for _ in range(N):
    simulate(rand)

predicts = ""
for _ in range(100):
    if simulate(rand):
        predicts += "o"
    else:
        predicts += "x"

io.sendlineafter(b"> ", predicts.encode())
print(io.recvall().strip().decode())
io.close()
