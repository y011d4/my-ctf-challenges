import os
import signal
from random import SystemRandom

random = SystemRandom()
flag = os.getenv("FLAG", "FAKEFLAG{THIS_IS_FAKE}")


if __name__ == "__main__":
    signal.alarm(60)

    try:
        # parameter setup
        p = int(input("p = "))
        assert p.bit_length() >= 256
        assert is_prime(p)
        a = int(input("a = "))
        b = int(input("b = "))
        E = EllipticCurve(GF(p), [a, b])
        assert not E.is_singular()
        assert 0 < a < p
        assert 0 < b < p

        # DLP in GF(p)
        g = GF(p)(input("g = "))
        x = random.randint(0, p - 1)
        h = g**x
        print(f"{h = }")
        x_ = int(input("x = "))

        # DLP in E
        Gx = int(input("Gx = "))
        Gy = int(input("Gy = "))
        G = E(Gx, Gy)
        y = random.randint(0, p - 2 * int(sqrt(p)))  # order should be > p - 2 * sqrt(p)
        H = y * G
        print(f"{H = }")
        y_ = int(input("y = "))

        if x == x_ and y == y_:
            print(flag)
        else:
            print(f"{x = }, {y = }")
    except Exception:
        print("Something wrong...")
