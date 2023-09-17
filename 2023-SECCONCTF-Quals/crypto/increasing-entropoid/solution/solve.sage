import re
from dataclasses import dataclass
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm
from z3 import *


@dataclass
class EntropoidParams:
    p: int
    a3: int
    a8: int
    b2: int
    b7: int


@dataclass
class EntropoidPowerIndex:
    a: list[int]
    pattern: list[int]
    base: int


class Entropoid:
    def __init__(self, params: EntropoidParams) -> None:
        self.p = params.p
        self.Fp = GF(self.p)
        self.a3, self.a8, self.b2, self.b7 = (
            self.Fp(params.a3),
            self.Fp(params.a8),
            self.Fp(params.b2),
            self.Fp(params.b7),
        )
        self.a1 = (self.a3 * (self.a8 * self.b2 - self.b7)) / (self.a8 * self.b7)
        self.a4 = (self.a8 * self.b2) / self.b7
        self.b1 = -((self.b2 * (self.a8 - self.a3 * self.b7)) / (self.a8 * self.b7))
        self.b5 = (self.a3 * self.b7) / self.a8

    def __call__(self, x1: int, x2: int) -> "EntropoidElement":
        return EntropoidElement(x1, x2, self)

    def random_power_index(self, base: int) -> EntropoidPowerIndex:
        size = ceil(log(self.p) / log(base))
        a_num = Integer(randrange(1, self.p))
        a = a_num.digits(base, padto=size)
        pattern_num = Integer(randrange(0, (base - 1) ** size - 1))
        pattern = pattern_num.digits(base - 1, padto=size)
        return EntropoidPowerIndex(a=a, pattern=pattern, base=base)


class EntropoidElement:
    def __init__(self, x1: int, x2: int, entropoid: Entropoid) -> None:
        self.entropoid = entropoid
        Fp = entropoid.Fp
        self.x1 = Fp(x1)
        self.x2 = Fp(x2)

    def __mul__(self, other) -> "EntropoidElement":
        e = self.entropoid
        x1 = e.a8 * self.x2 * other.x1 + e.a3 * self.x2 + e.a4 * other.x1 + e.a1
        x2 = e.b7 * self.x1 * other.x2 + e.b2 * self.x1 + e.b5 * other.x2 + e.b1
        return self.entropoid(x1, x2)

    def __repr__(self) -> str:
        return f"({self.x1}, {self.x2})"

    def __eq__(self, other) -> bool:
        return (
            self.entropoid == other.entropoid
            and self.x1 == other.x1
            and self.x2 == other.x2
        )

    def __pow__(self, other: EntropoidPowerIndex) -> "EntropoidElement":
        a, pattern, base = other.a, other.pattern, other.base
        k = len(a)
        w = self
        ws = [w]
        for p_i in pattern[1:]:
            ws.append(calc_r(ws[-1], base, p_i))
        j = a.index(next(filter(lambda x: x != 0, a)))
        a_j = a[j]
        if a_j == 1:
            x = ws[j]
        else:
            wj = ws[j]
            x = calc_r(wj, a_j, pattern[j] % (a_j - 1))
        for i in range(j + 1, k):
            a_i = a[i]
            if a_i == 0:
                continue
            if a_i == 1:
                tmp = ws[i]
            else:
                wi = ws[i]
                tmp = calc_r(wi, a_i, pattern[i] % (a_i - 1))
            if pattern[i - 1] % 2 == 0:
                x = tmp * x
            else:
                x = x * tmp
        return x

    def to_bytes(self) -> bytes:
        p = self.entropoid.p
        assert p.bit_length() % 8 == 0
        size = p.bit_length() // 8
        return long_to_bytes(int(self.x1), size) + long_to_bytes(int(self.x2), size)


class DH:
    def __init__(self, g: EntropoidElement, base: int) -> None:
        E = g.entropoid
        self.__priv = E.random_power_index(base)
        self.pub = g**self.__priv

    def gen_share(self, other_pub: EntropoidElement) -> EntropoidElement:
        return other_pub**self.__priv


def calc_r(x: EntropoidElement, a: int, i: int) -> EntropoidElement:
    assert 0 <= i <= a - 2

    def calc_to_left(
        y: EntropoidElement, x: EntropoidElement, a: int
    ) -> EntropoidElement:
        res = y
        for _ in range(a):
            res = x * res
        return res

    return calc_to_left((calc_to_left(x, x, i) * x), x, a - i - 2)


def sigma(x: EntropoidElement) -> EntropoidElement:
    E = x.entropoid
    p = x.entropoid.p
    left_one = E(
        -(E.a3 * pow(E.a8, -1, p)) + pow(E.b7, -1, p), 1 * pow(E.a8, -1, p) - E.b2 * pow(E.b7, -1, p)
    )
    return x * left_one


def FtoE(x: tuple[int, int], E: Entropoid) -> EntropoidElement:
    return EntropoidElement(x[0] / E.b7 - E.a3 / E.a8, x[1] / E.a8 - E.b2 / E.b7, E)


def EtoF(x: EntropoidElement) -> tuple[int, int]:
    e = x.entropoid
    return e.b7 * x.x1 + e.a3 * e.b7 / e.a8, e.a8 * x.x2 + e.a8 * e.b2 / e.b7


def solve_dlp(h: int, g: int, p: int):
    return GF(p)(h).log(g)


def solve_delp(pub: EntropoidElement, g: EntropoidElement, p: int):
    G = GF(p).multiplicative_generator()
    alpha1, alpha2 = EtoF(g)
    beta1, beta2 = EtoF(sigma(g))
    gamma1, gamma2 = EtoF(pub)
    mat = matrix(Zmod(p - 1), [[solve_dlp(alpha1, G, p), solve_dlp(alpha2, G, p)], [solve_dlp(beta1, G, p), solve_dlp(beta2, G, p)]])
    vec = vector(Zmod(p - 1), [solve_dlp(gamma1, G, p), solve_dlp(gamma2, G, p)])
    sol = mat.solve_left(vec)
    return sol.change_ring(ZZ)


class RandomZ3:
    N = int(624)
    M = int(397)
    MATRIX_A = int(0x9908B0DF)
    UPPER_MASK = int(0x80000000)
    LOWER_MASK = int(0x7FFFFFFF)

    def __init__(self):
        self._solver = Solver()
        self._state_int = BitVec("s", int(32 * self.N))
        self._state = [Extract(int(i+31), int(i), self._state_int) for i in range(0, 32 * self.N, 32)]
        self._solver.add(self._state[0] == int(0x80000000))
        self._counter = self.N

    def _bit_shift_right_xor_rev(self, x, shift):
        i = 1
        y = x
        while i * shift < 32:
            if type(y) == int:
                z = int(y >> shift)
            else:
                z = LShR(y, shift)
            y = x ^^ z
            i += 1
        return y

    def _bit_shift_left_xor_rev(self, x, shift, mask):
        i = 1
        y = x
        while i * shift < 32:
            z = y << int(shift)
            y = x ^^ (z & int(mask))
            i += 1
        return y

    def _untemper(self, x):
        x = self._bit_shift_right_xor_rev(x, 18)
        x = self._bit_shift_left_xor_rev(x, 15, 0xEFC60000)
        x = self._bit_shift_left_xor_rev(x, 7, 0x9D2C5680)
        x = self._bit_shift_right_xor_rev(x, 11)
        return x

    def _update_mt(self):
        N = self.N
        M = self.M
        MATRIX_A = self.MATRIX_A
        UPPER_MASK = self.UPPER_MASK
        LOWER_MASK = self.LOWER_MASK
        for kk in range(N - M):
            y = (self._state[kk] & UPPER_MASK) | (self._state[kk + 1] & LOWER_MASK)
            if type(y) == int:
                self._state[kk] = self._state[kk + M] ^^ (y >> 1) ^^ (y % 2) * MATRIX_A
            else:
                self._state[kk] = self._state[kk + M] ^^ LShR(y, int(1)) ^^ (y % int(2)) * MATRIX_A
        for kk in range(N - M, N - 1):
            y = (self._state[kk] & UPPER_MASK) | (self._state[kk + 1] & LOWER_MASK)
            if type(y) == int:
                self._state[kk] = self._state[kk + (M - N)] ^^ (y >> 1) ^^ (y % 2) * MATRIX_A
            else:
                self._state[kk] = self._state[kk + (M - N)] ^^ LShR(y, int(1)) ^^ (y % int(2)) * MATRIX_A
        y = (self._state[N - 1] & UPPER_MASK) | (self._state[0] & LOWER_MASK)
        if type(y) == int:
            self._state[N - 1] = self._state[M - 1] ^^ (y >> 1) ^^ (y % 2) * MATRIX_A
        else:
            self._state[N - 1] = self._state[M - 1] ^^ LShR(y, int(1)) ^^ (y % int(2)) * MATRIX_A

    def _count_and_update_if_necessary(self):
        if self._counter == self.N:
            self._counter -= self.N
            self._update_mt()
        ret = self._counter
        self._counter += 1
        return ret

    def add_random32_constraint(self, rand):
        i = self._count_and_update_if_necessary()
        if rand is None:
            return
        self._solver.add(self._state[i] == self._untemper(rand))

    def solve(self, all=False):
        if all:
            state_rec_list = []
            while True:
                if self._solver.check() != sat:
                    break
                m = self._solver.model()
                tmp_state_int = m[self._state_int].as_long()
                state_rec = [int((tmp_state_int >> (32*i)) % 2**32) for i in range(self.N)]
                state_rec_list.append(state_rec)
                self._solver.add(self._state_int != tmp_state_int)
            return state_rec_list
        else:
            assert self._solver.check() == sat
            m = self._solver.model()
            tmp_state_int = m[self._state_int].as_long()
            state_rec = [int((tmp_state_int >> (32*i)) % 2**32) for i in range(self.N)]
            return state_rec

    def set_python_random_state(self, state):
        random = current_randstate().python_random()
        random.setstate((int(3), tuple(state + [int(624)]), None))


entropoid_params_debug = EntropoidParams(
    p=18446744073709550147,  # safe prime
    a3=1,
    a8=3,
    b2=3,
    b7=7,
)
E_debug = Entropoid(entropoid_params_debug)


# Parse output.txt
pub_a_list = []
pub_b_list = []
with open("./output.txt") as fp:
    for _ in range(257):
        line = fp.readline()
        pub_a1, pub_a2, pub_b1, pub_b2 = map(int, re.findall(r"\((\d*), (\d*)\) \((\d*), (\d*)\)", line)[0])
        pub_a_list.append(E_debug(pub_a1, pub_a2))
        pub_b_list.append(E_debug(pub_b1, pub_b2))
    enc = bytes.fromhex(fp.readline()[6:])


# Recover rands
g = E_debug(13, 37)
rands = []
for i in tqdm(range(256)):
    es = solve_delp(pub_a_list[i], g, E_debug.p)
    rands.append(int(es[0] + es[1] - 1))
    es = solve_delp(pub_b_list[i], g, E_debug.p)
    rands.append(int(es[0] + es[1] - 1))


# Recover rand state
p = E_debug.p
base_a = 17
base_b = 33
size_a = ceil(log(p) / log(base_a))
size_b = ceil(log(p) / log(base_b))

random_z3 = RandomZ3()
L = 256
for idx in tqdm(range(0, 2 * L, 2)):
    random_z3.add_random32_constraint(rands[idx+0] % int(2**32))
    random_z3.add_random32_constraint(rands[idx+0] >> int(32))
    for _ in range(2):  # ((base_a-1)**size_a-1).nbits() == 64
        _ = random_z3.add_random32_constraint(None)
    random_z3.add_random32_constraint(rands[idx+1] % int(2**32))
    random_z3.add_random32_constraint(rands[idx+1] >> int(32))
    for _ in range(3):  # ((base_b-1)**size_b-1).nbits() == 65
        _ = random_z3.add_random32_constraint(None)
state = random_z3.solve()
random_z3.set_python_random_state(state)

for _ in range(L):
    _ = randrange(1, p)
    _ = randrange(0, (base_a-1)**size_a-1)
    _ = randrange(1, p)
    _ = randrange(0, (base_b-1)**size_b-1)


# decrypt using shared key
entropoid_params = EntropoidParams(
    p=0xF557D412B06B9370BA144A3FA9E4F519B4263C5232D86089B661A9D957A9DCE371F01AD4E36642F5A6377D80FC195889400EBE9C2AC91E785C841BCC3FC97ECCA78B19962692D9C049876A785F72CB66416BF5FFCF09BB8EE54D5B4501E9FD3ACC7FD87BB3A0163BECC363994C9C91E5B624AC59D032635B5CAE8B9E04FB1056F69E7493D7F00498F8CE98CA535B81FDA18BEF2DB0AE82377BDDEAFBAA1D8FDA157C923D66D1330B149213A2BF56E25755F743BDB2486D976EDF01C91D963481C31B6634A2B9F7FDC9FA63DF5DEC5F55D3BBF28E43863F26A55FD6AD668C9087228464C1D5EE4F83E82869C401568B8C1E6420423CF110091548CBAB57DBE4F7,  # safe prime
    a3=1,
    a8=3,
    b2=3,
    b7=7,
)
E = Entropoid(entropoid_params)
priv_a = E.random_power_index(base_a)
priv_b = E.random_power_index(base_b)
g = E(13, 37)
pub_a = g ** priv_a
s_ab = (g ** priv_a) ** priv_b
s_ab = (g ** priv_b) ** priv_a
key = sha256(s_ab.to_bytes()).digest()
cipher = AES.new(key, AES.MODE_ECB)
msg = unpad(cipher.decrypt(enc), 16).decode()
print(msg)
