import os
import signal
from secrets import randbelow

from Crypto.Util.number import isPrime

flag = os.getenv("FLAG", "SECCON{this_is_not_a_flag}")


if __name__ == "__main__":
    signal.alarm(120)

    p = int(input("Your favorite prime p (hex) > "), 16)
    if not isPrime(p) and p.bit_length() >= 512:
        print("p must be a prime")
        exit()
    q = int(input("Your favorite prime q (hex) > "), 16)
    if not isPrime(q) and q.bit_length() >= 512:
        print("q must be a prime")
        exit()
    n = p * q

    g = n // 2
    h = n // 3
    x = randbelow(2**512)
    r = (pow(x, g, n) + pow(x, h, n)) % n
    print(f"{r = }")

    guess_x = int(input("Guess x > "))
    if x == guess_x:
        print(flag)
    else:
        print("Wrong...")
