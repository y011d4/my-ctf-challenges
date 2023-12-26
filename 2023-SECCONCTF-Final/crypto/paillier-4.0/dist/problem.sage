import os
from dataclasses import dataclass
from secrets import randbelow
from typing import Optional

from Crypto.Util.number import bytes_to_long, getPrime

from sage.algebras.quatalg.quaternion_algebra_element import QuaternionAlgebraElement_generic


@dataclass
class Pubkey:
    n: int
    g: QuaternionAlgebraElement_generic

    def __repr__(self) -> str:
        return "n = {self.n}\ng = {self.g}"  # Oh, I forgot f-string...


@dataclass
class Privkey:
    l: int
    pubkey: Pubkey

    @classmethod
    def generate(cls, pbits: int = 1024) -> "Privkey":
        p = getPrime(pbits)
        q = getPrime(pbits)
        n = p * q
        Q = QuaternionAlgebra(Zmod(n**2), -1, -1)
        g = 1 + Q.random_element() * n
        l = lcm(p - 1, q - 1)
        return Privkey(l=l, pubkey=Pubkey(n=n, g=g))

    def export_pubkey(self) -> Pubkey:
        return Pubkey(n=self.pubkey.n, g=self.pubkey.g)


class Paillier:
    def __init__(self, privkey: Optional[Privkey], pubkey: Pubkey) -> None:
        self.privkey = privkey
        self.pubkey = pubkey

    @classmethod
    def from_privkey(cls, privkey: Privkey) -> "Paillier":
        return Paillier(privkey=privkey, pubkey=privkey.export_pubkey())

    @classmethod
    def from_pubkey(cls, pubkey: Pubkey) -> "Paillier":
        return Paillier(privkey=None, pubkey=pubkey)

    def encrypt(self, m: int):
        n = self.pubkey.n
        g = self.pubkey.g
        assert 1 <= m < n
        return g**m * pow(randbelow(n**2), n, n**2)

    def L(self, u: QuaternionAlgebraElement_generic):
        n = self.pubkey.n
        g = self.pubkey.g
        Q = g.parent()
        i, j, k = Q.gens()
        return (
            int(u[0] - 1) // n
            + int(u[1]) // n * i
            + int(u[2]) // n * j
            + int(u[3]) // n * k
        )

    def decrypt(self, c):
        if self.privkey is None:
            raise RuntimeError("privkey is not defined")
        n = self.pubkey.n
        g = self.pubkey.g
        l = self.privkey.l
        Q = g.parent()
        i, j, k = Q.gens()
        tmp = self.L(c**l) * self.L(g**l) ** -1
        return (
            int(tmp[0] % n)
            + int(tmp[1] % n) * i
            + int(tmp[2] % n) * j
            + int(tmp[3] % n) * k
        )


if __name__ == "__main__":
    privkey = Privkey.generate(1024)
    pubkey = privkey.export_pubkey()
    print(pubkey)
    paillier = Paillier.from_privkey(privkey)
    m1 = bytes_to_long(b"I have implemented Paillier 4.0. Can you break it?")
    m2 = bytes_to_long(os.getenvb(b"FLAG", b"FAKEFLAG{THIS_IS_FAKE}"))
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)
    print(f"{c1 = }")
    print(f"{c2 = }")
