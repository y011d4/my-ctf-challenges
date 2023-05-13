import os
import random
import signal

from Crypto.Util.number import bytes_to_long, getStrongPrime

flag = os.getenv("FLAG", "FAKEFLAG{THIS_IS_FAKE}").encode()


def rotl(n: int, n_bits: int, rot_bits: int) -> int:
    rot_bits = rot_bits % n_bits
    return ((n << rot_bits) & (2**n_bits - 1)) | (n >> (n_bits - rot_bits))


def pad(s: bytes, size: int) -> bytes:
    return random.randbytes(size - len(s)) + s


def encrypt(pt: bytes, e: int, n: int) -> int:
    pt = pad(pt, n.bit_length() // 8 - 1)
    return pow(bytes_to_long(pt), e, n)


if __name__ == "__main__":
    signal.alarm(60)
    e = 0x10001
    n_bits = 1024
    p_bits = n_bits // 2
    p = getStrongPrime(p_bits, e=e)
    q = getStrongPrime(p_bits, e=e)
    n = p * q
    c = encrypt(flag, e, n)
    print(f"{n = }")
    print(f"{c = }")
    try:
        while True:
            n_sushi = int(input("How many sushi?> "))
            assert n_sushi <= 1024
            sushi_plate = []
            for _ in range(n_sushi):
                p, q = rotl(p, p_bits, 1), rotl(q, p_bits, 1)
                n = p * q
                c = encrypt(flag, e, n)
                sushi_plate.append(c)
            print(", ".join(map(str, sushi_plate)))
    except Exception:
        print("Something wrong...")
