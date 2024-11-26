from dataclasses import dataclass
from secrets import randbelow
from typing import NewType

from Crypto.Util.number import getPrime

Pt = NewType("Pt", int)
Ct = NewType("Ct", int)


@dataclass(frozen=True)
class Pubkey:
    n: int

    def __post_init__(self) -> None:
        assert 2 <= self.g < self.n

    @property
    def g(self) -> int:
        return self.n // 2  # We fix g in order to avoid malicious g


@dataclass(frozen=True)
class Privkey:
    p: int
    q: int
    pub: Pubkey

    def export_pubkey(self) -> Pubkey:
        return Pubkey(self.pub.n)

    @classmethod
    def generate(cls, pbits: int) -> "Privkey":
        p = getPrime(pbits)
        q = getPrime(pbits)
        n = p**2 * q
        return Privkey(p, q, Pubkey(n))


class Cryptosystem:
    """https://en.wikipedia.org/wiki/Okamoto%E2%80%93Uchiyama_cryptosystem"""

    def __init__(self, pubkey: Pubkey, privkey: Privkey | None):
        self.pubkey = pubkey
        self.privkey = privkey

    @classmethod
    def from_privkey(cls, privkey: Privkey) -> "Cryptosystem":
        return Cryptosystem(privkey.export_pubkey(), privkey)

    @classmethod
    def from_pubkey(cls, pubkey: Pubkey) -> "Cryptosystem":
        return Cryptosystem(pubkey, None)

    def encrypt(self, m: Pt) -> Ct:
        n = self.pubkey.n
        g = self.pubkey.g
        h = pow(g, n, n)
        return Ct(pow(g, m, n) * pow(h, randbelow(n), n) % n)

    def add(self, a: Ct, b: Ct) -> Ct:
        return Ct(a * b % self.pubkey.n)

    def mul(self, a: Ct, k: Pt) -> Ct:
        return Ct(pow(a, k, self.pubkey.n))

    def L(self, x: int):
        if self.privkey is None:
            raise RuntimeError("privkey is not defined")
        assert x % self.privkey.p == 1
        return (x - 1) // self.privkey.p

    def decrypt(self, c: int) -> int:
        if self.privkey is None:
            raise RuntimeError("privkey is not defined")
        p = self.privkey.p
        g = self.pubkey.g
        a = self.L(pow(c, p - 1, p**2))
        b = self.L(pow(g, p - 1, p**2))
        return a * pow(b, -1, p) % p
