import os
import secrets
import signal

FLAG = os.getenv("FLAG", "FAKEFLAG{THIS_IS_FAKE}")


if __name__ == "__main__":
    signal.alarm(333)
    p = int(input("What's your favorite 333-bit p: "))
    if not is_prime(p) or p.bit_length() != 333:
        print("Invalid p")
        exit()
    order = p**2 - 1
    x = secrets.randbelow(order)
    Q = QuaternionAlgebra(Zmod(p), -1, -1)
    g = Q.random_element()
    h = g**x
    print(f"{g = }")
    print(f"{h = }")
    _x = int(input("Guess x: "))
    if g**_x == h:
        print(FLAG)
    else:
        print("NO FLAG")
