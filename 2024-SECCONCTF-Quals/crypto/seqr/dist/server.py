import os
import signal
from secrets import randbelow

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecdsa import SigningKey, SECP256k1
from gmpy2 import legendre

flag = os.getenvb(b"FLAG", b"SECCON{this_is_not_a_flag}")

menu = """
1. sign
2. get pubkey
3. encrypt flag
"""


class PRNG:
    """Legendre PRF is believed to be secure
    ex. https://link.springer.com/chapter/10.1007/0-387-34799-2_13
    """

    def __init__(self, initial_state: int, p: int) -> None:
        self._state = initial_state
        self.p = p

    def __call__(self, n_bit: int) -> int:
        out = 0
        for _ in range(n_bit):
            out <<= 1
            tmp = legendre(self._state, self.p)
            out |= (1 + tmp) // 2 if tmp != 0 else 1
            self._state += 1
            self._state %= self.p
        return out


if __name__ == "__main__":
    signal.alarm(600)

    p = int(input("Your favorite 256-bit prime (hex) > "), 16)
    if p.bit_length() != 256:
        print("p must be 256-bit")
        exit()
    a = randbelow(p)
    prng = PRNG(a, p)

    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    assert sk.privkey is not None
    d = sk.privkey.secret_multiplier

    print(menu)

    n_sign = 0
    while True:
        option = int(input("option > "))
        if option == 1:
            if n_sign >= 3333:
                print("Too many signs")
                exit()
            msg = bytes.fromhex(input("msg (hex) > "))
            k = prng(256)
            signature = sk.sign(msg, k=k)
            print(f"signature = {signature.hex()}")
            n_sign += 1
        elif option == 2:
            print(f"pubkey = {vk.to_string().hex()}")
        elif option == 3:
            # You can get the flag only if you break both of PRNG and ECDSA.
            key = (d ^ a).to_bytes(32, "big")
            enc = AES.new(key, AES.MODE_ECB).encrypt(pad(flag, 16))
            print(f"enc = {enc.hex()}")
        else:
            exit()
